#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include "Enclave_u.h"
#include "sgx_tseal.h"
#include "sgx_urts.h"

#include "Blind.h"
#include "Ocall.h"
#include "sgx_utils/sgx_utils.h"

// For networking
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT "9876"
#define CHUNK_SIZE 4096

#ifndef DEBUG
#define DEBUG
#endif

#ifdef DEBUG
#define DEBUG_LOG(msg) do { std::cout << msg << std::endl; } while(0);
#endif

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// Chunk number
uint64_t global_chunk_no = 0;

bool bind(struct addrinfo* servinfo_res, int* sock_fd) {
    struct addrinfo* p;
    for (p = servinfo_res; p != NULL; p = p->ai_next){
        *sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (*sock_fd == -1) {
            perror("server: socket");
            continue;
        }
        int magic = 1;
        if (setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &magic, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }
        if (bind(*sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(*sock_fd);
            perror("server: bind");
            continue;
        }
        break;
    }
    return p != NULL;
}

int bind_and_listen() {
    struct addrinfo* servinfo;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int addrinfo_status;
    if ((addrinfo_status = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        perror(gai_strerror(addrinfo_status));
        return 1;
    }

    int sock_fd;
    if(!bind(servinfo, &sock_fd)) {
        std::cerr << "Server: Failed to bind." << std::endl;
        return 1;
    }
    freeaddrinfo(servinfo);

    if (listen(sock_fd, 10 /* backlog */) == -1) {
        perror("listen");
        return 1;
    }
    std::cout << "Listening on port " << PORT << std::endl;

    return sock_fd;
}

std::string create_chunk_file_name(uint64_t chunk_no) {
    std::ostringstream chunk_file_name;
    chunk_file_name << "chunks/" << chunk_no;
    return chunk_file_name.str();
}

bool unseal_and_reconstruct_file(const std::string& file_name) {
    uint64_t chunk_begin;
    uint64_t chunk_end;
    std::ifstream file_desc(file_name + ".desc", std::ios::binary);
    if (!file_desc) {
        std::cerr << "Problem opening file_desc when unsealing" << std::endl;
        exit(1);
    }
    file_desc >> chunk_begin;
    file_desc >> chunk_end;
    file_desc.close();

    std::ofstream unsealed_file(file_name, std::ios::binary);

    if (!unsealed_file) {
        std::cerr << "Problem opening file when unsealing" << std::endl;
        exit(1);
    }

    size_t sealed_size = sizeof(sgx_sealed_data_t) + CHUNK_SIZE;
    char sealed_buf[sealed_size];
    uint64_t current_chunk = chunk_begin;
    while (current_chunk < chunk_end) {
        std::ifstream chunk_file(create_chunk_file_name(current_chunk++));
        chunk_file.read(sealed_buf, sealed_size);
        chunk_file.close();

        char unsealed_buf[CHUNK_SIZE];
        sgx_status_t ecall_success;
        sgx_status_t status = unseal(global_eid, &ecall_success, (sgx_sealed_data_t*)sealed_buf, sealed_size, (uint8_t*)unsealed_buf, CHUNK_SIZE);
        if (!is_ecall_successful(status, "Unsealing failed. Aborting.", ecall_success)) {
            return false;
        }

        size_t write_len = CHUNK_SIZE;
        // handling last chunk, remove trailing 0s
        if (current_chunk == chunk_end) {
            for (int i = CHUNK_SIZE-1; i >= 0; --i) {
                if (unsealed_buf[i] == 0) {
                    --write_len;
                } else {
                    break;
                }
            }
        }
        unsealed_file.write(unsealed_buf, write_len);
        memset(sealed_buf, 0, sealed_size);
        memset(unsealed_buf, 0, CHUNK_SIZE);
    }
    return true;
}

bool seal_and_store(std::ofstream& file, char* buffer) {
    size_t sealed_size = sizeof(sgx_sealed_data_t) + CHUNK_SIZE;
    char sealed_buf[sealed_size];
    sgx_status_t ecall_success;
    sgx_status_t status = seal(global_eid, &ecall_success, (uint8_t*)buffer, CHUNK_SIZE, (sgx_sealed_data_t*)sealed_buf, sealed_size);
    if (!is_ecall_successful(status, "Sealing failed. Aborting.", ecall_success)) {
        return false;
    }
    file.write(sealed_buf, sealed_size);
    return true;
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Failed to initialize enclave" << std::endl;
        return 1;
    }
    // Open connection, block to receive data
    int sock_fd = bind_and_listen();

    int new_conn_fd;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;

    while(true) {
        sin_size = sizeof(their_addr);
        new_conn_fd = accept(sock_fd, (struct sockaddr*)&their_addr, &sin_size);

        if (new_conn_fd == -1) {
            perror("accept");
            continue;
        }

        // sockaddr magic: http://beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html
        char client_addr[INET6_ADDRSTRLEN];
        if (their_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, (struct sockaddr_in6*)&their_addr, client_addr, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET, (struct sockaddr_in*)&their_addr, client_addr, INET6_ADDRSTRLEN);
        }
        std::cout << client_addr << " connected." << std::endl;

        char buffer[CHUNK_SIZE];
        int bytes_recv = 0;

        // Receive blinded hash
        if ((bytes_recv = recv(new_conn_fd, buffer, CHUNK_SIZE, 0)) != 384) {
            std::cerr << "Blinded hash size error. Disconnect" << std::endl;
            close(new_conn_fd);
            continue;
        }

        // ecall to sign the data
        char signed_buf[384]; // Modulus size of the RSA key in bytes
        blind_sign_digest(buffer, bytes_recv, signed_buf);
        // Send back signed data
        if (send(new_conn_fd, signed_buf, 384, 0) == -1) {
            perror("send");
            continue;
        }
        memset(buffer, 0, sizeof(buffer));

        // Receive file name
        if ((bytes_recv = recv(new_conn_fd, buffer, CHUNK_SIZE, 0)) > 256) {
            std::cerr << "File name longer than 255 chars. Disconnect" << std::endl;
            close(new_conn_fd);
            continue;
        }
        if (send(new_conn_fd, "ok", 3, 0) == -1) {
            perror("send");
            continue;
        }

        // Receive file
        std::string filename(buffer, bytes_recv);
        std::ofstream file_desc(filename + ".desc", std::ios::binary);
        if (!file_desc) {
            std::cerr << "Error creating file.desc" << std::endl;
            exit(1);
        }

        // Starting chunk_no of this file (inclusive)
        file_desc << global_chunk_no << std::endl;
        while((bytes_recv = recv(new_conn_fd, buffer, CHUNK_SIZE, 0)) > 0) {
            std::ofstream chunk_file(create_chunk_file_name(global_chunk_no++), std::ios::binary);
            seal_and_store(chunk_file, buffer);
            chunk_file.close();
            memset(buffer, 0, sizeof(buffer));
        }
        // Ending chunk_no of this file (exclusive)
        file_desc << global_chunk_no << std::endl;
        file_desc.close();
        std::cout << "Done. Close connection." << std::endl;
        close(new_conn_fd);

        // Test unseal file
        // unseal_and_reconstruct_file(filename);
        // DEBUG_LOG("Done unsealing. Can check for diff.");
    }
    sgx_destroy_enclave(global_eid);
    return 0;
}
