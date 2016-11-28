#include <cstdio>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"

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

#define PORT "9876"

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

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
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

int main(int argc, char const *argv[]) {
    if (initialize_enclave() < 0) {
        std::cout << "Failed to initialize enclave" << std::endl;
        return 1;
    }

    // Open connection, block to receive data
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

        if (!fork()) { // is child process
            // Child doesn't need to listen to new connections.
            close(sock_fd);
            char buffer[1024];
            int bytes_recv = 0;
            while((bytes_recv = recv(new_conn_fd, buffer, 1024, 0)) > 0) {
                buffer[bytes_recv] = '\0';
                std::cout << buffer;
                if (send(new_conn_fd, buffer, strlen(buffer), 0) == -1) {
                    perror("send");
                }
            }
            std::cout << "Close" << std::endl;
            close(new_conn_fd);
            exit(0);
        }
        // Parent doesn't need to handle the new connection
        close(new_conn_fd);
    }

    // Data received, sign with pvt key

    // send back signed data.

    // Receive file

    // Seal and store

    return 0;
}
