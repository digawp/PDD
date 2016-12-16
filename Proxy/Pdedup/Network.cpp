#include <cstdio>
#include <cstring>
#include <iostream>

// Includes for networking
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "Network.h"

bool connect(struct addrinfo* ai_results, int* socket_fd) {
    // Result pointer
    struct addrinfo* rp;

    for (rp = ai_results; rp != NULL; rp = rp->ai_next) {
        struct sockaddr_in* addr;
        addr = (struct sockaddr_in *)rp->ai_addr;

        *socket_fd =
            socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (*socket_fd == -1) {
            perror("Error when opening a socket.");
            continue;
        }

        int connect_status =
            ::connect(*socket_fd, rp->ai_addr, rp->ai_addrlen);
        if (connect_status < 0) {
            close(*socket_fd);
            perror("Error when trying to connect.");
            continue;
        }
        break; // connect successful
    }

    if (rp == NULL) {
        // Ran out of ai_results, means failed to connect.
        return false;
    }
    return true;
}

int connect_to_s(){
    int socket_fd;
    struct addrinfo* addrinfo_res;

    // Resolve the URL to its IP Address
    int addrinfo_status =
        getaddrinfo("localhost", "6789", NULL, &addrinfo_res);
    if (addrinfo_status != 0) {
        // Error when getting address info.
        perror(gai_strerror(addrinfo_status));
        return -1;
    }

    // Attempt to connect to the server
    bool connect_success = connect(addrinfo_res, &socket_fd);
    if (!connect_success) {
        perror("Cannot connect to any of the results");
        return -1;
    }
    freeaddrinfo(addrinfo_res);
    return socket_fd;
}

bool send(int socket_fd, const char* data, size_t data_len) {
    if (send(socket_fd, data, data_len, 0) == -1) {
        perror("send");
        return false;
    }
    return true;
}

size_t receive(int socket_fd, char* buffer, size_t buf_len) {
    return recv(socket_fd, buffer, buf_len, 0);
}
