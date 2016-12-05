#ifndef PDD_CLIENT_NETWORK_H_
#define PDD_CLIENT_NETWORK_H_

/**
 * @brief      Connects to Enterprise Proxy P.
 *
 * @return     The socket file descriptor of the connection with P.
 */
int connect_to_p(void);

/**
 * @brief      Sends data of the specified data_len length through the specified
 *             socket file descriptor socket_fd
 *
 * @param[in]  socket_fd  The socket file descriptor to send the data to
 * @param[in]  data       The data
 * @param[in]  data_len   The data length
 *
 * @return     true if send successful, false otherwise
 */
bool send(int socket_fd, const char* data, size_t data_len);

/**
 * @brief      Receives data from the speciifed socket descriptor, storing it
 *             into the specified buffer of size buf_len
 *
 * @param[in]  socket_fd  The socket file descriptor to receive data from
 * @param      buffer     The buffer
 * @param[in]  buf_len    The buffer length
 *
 * @return     The number of bytes received.
 */
size_t receive(int socket_fd, char* buffer, size_t buf_len);

#endif // PDD_CLIENT_NETWORK_H_
