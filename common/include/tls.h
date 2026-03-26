#ifndef SSL_H
#define SSL_H
#include <openssl/err.h>
#include <openssl/ssl.h>

/**
 * @brief Creates a SSL_CTX object with server settings
 *
 * @param cert Path to server_cert.pem
 * @param key path to server_key.pem
 *
 * @return SSL_CTX* object that holds the ssl context. Used for creating
 *         SSL connections
 */
SSL_CTX* tls_server_config(const char* cert, const char* key);

/**
 * @brief Initalizes the server returning a BIO acceptor object, used to accept
 *        new client connections.
 *
 * @param ctx Configured SSL_CTX object
 * @param port Port used for server
 *
 * @return BIO* acceptor object that can be used to accept new client
 * connections
 */
BIO* tls_server_init(SSL_CTX* ctx, const char* port);

/**
 * @brief Accepts a new client connection
 *
 * @param ctx Configured SSL_CTX object
 * @param abio Acceptor BIO object
 *
 * @return SSL* Pointer to established SSL session or NULL
 */
SSL* tls_server_accept(SSL_CTX* ctx, BIO* abio);

/**
 * @brief Configures SSL_CTX for client
 *
 * @param cert Path to CA-cert.pem
 *
 * @return SSL_CTX* Configured SSL_CTX
 */
SSL_CTX* tls_client_config(const char* cert);

/**
 * @brief Connects to a server
 *
 * @param ctx Configured SSL_CTX
 * @param addr Server address
 * @param port Server port
 *
 * @return SSL* Established SSL connection
 */
SSL* tls_client_connect(SSL_CTX* ctx, const char* addr, const char* port);

/**
 * @brief Reads from an SSL connection
 *
 * @param ssl The established SSL session
 * @param buf Buffer to read into
 * @param len Max size of buffer
 *
 * @return ssize_t # of bytes read or -1 on failure
 */
ssize_t tls_read(SSL* ssl, void* buf, size_t len);

/**
 * @brief Writes to an SSL connection
 *
 * @param ssl The established SSL session
 * @param buf Buffer to write from
 * @param write_bytes Bytes to write
 *
 * @return ssize_t # of bytes written or -1 on failure
 */
ssize_t tls_write(SSL* ssl, void* buf, size_t write_bytes);

/**
 * @brief Cleans up TLS session.
 *
 * Should not be used on a client bio or server bio. Only an acceptor bio.
 * These bios would be typically owned by the SSL session and be freed there.
 *
 * @param ctx - SSL_CTX object
 * @param bio - BIO acceptor object
 *
 */
void tls_cleanup(SSL_CTX* ctx, BIO* bio);
#endif
