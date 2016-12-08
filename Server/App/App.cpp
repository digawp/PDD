#include <cstdio>
#include <fstream>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_tseal.h"
#include "sgx_urts.h"

#include "Ocall.h"

// For networking
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define PORT "6789"
#define CHUNK_SIZE 4096

#ifndef DEBUG
#define DEBUG
#endif

#ifdef DEBUG
#define DEBUG_LOG(msg) do { std::cout << msg << std::endl; } while(0);
#endif

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    std::cout << ret << std::endl;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave() {
    char* token_path = "launch_token_file";
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    FILE* fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

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

bool unseal_file(const std::string& sealed_name, const std::string& unsealed_name) {
    size_t sealed_size = sizeof(sgx_sealed_data_t) + CHUNK_SIZE;
    char sealed_buf[sealed_size];
    std::ifstream sealed_file(sealed_name, std::ios::binary);
    std::ofstream unsealed_file(unsealed_name, std::ios::binary);
    sealed_file.read(sealed_buf, sealed_size);
    while(sealed_file.gcount() > 0) {
        char unsealed_buf[CHUNK_SIZE];
        int unseal_success;
        // Seal and store
        sgx_status_t status = unseal(global_eid, &unseal_success, (sgx_sealed_data_t*)sealed_buf, sealed_size, (uint8_t*)unsealed_buf, CHUNK_SIZE);
        if (status != SGX_SUCCESS || !unseal_success) {
            DEBUG_LOG("Sealing failed. Aborting.");
            print_error_message(status);
            return false;
        }

        size_t write_len = CHUNK_SIZE;
        // handling last chunk, remove trailing 0s
        if (sealed_file.peek() < 0) {
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
        sealed_file.read(sealed_buf, sealed_size);
    }
    return true;
}

bool seal_and_append(std::ofstream& file, char* buffer) {
    size_t sealed_size = sizeof(sgx_sealed_data_t) + CHUNK_SIZE;
    char sealed_buf[sealed_size];
    int seal_success;
    // Seal and store
    sgx_status_t status = seal(global_eid, &seal_success, (uint8_t*)buffer, CHUNK_SIZE, (sgx_sealed_data_t*)sealed_buf, sealed_size);
    if (status != SGX_SUCCESS || !seal_success) {
        DEBUG_LOG("Sealing failed. Aborting.");
        print_error_message(status);
        return false;
    }
    file.write(sealed_buf, sealed_size);
    return true;
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave() < 0) {
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

        // Receive file
        std::ofstream output("temp.sealed", std::ios::binary);

        while((bytes_recv = recv(new_conn_fd, buffer, CHUNK_SIZE, 0)) > 0) {
            seal_and_append(output, buffer);
            memset(buffer, 0, sizeof(buffer));
        }
        output.close();
        std::cout << "Done. Close connection." << std::endl;
        close(new_conn_fd);

        // Test unseal file
        unseal_file("temp.sealed", "temp.unsealed");
        DEBUG_LOG("Done unsealing. Can check for diff.");
    }
    sgx_destroy_enclave(global_eid);
    return 0;
}
