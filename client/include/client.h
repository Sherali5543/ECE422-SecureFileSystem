#ifndef CLIENT_H
#define CLIENT_H
#include "http.h"
#include "tls.h"

void disconnect_server(SSL* ssl, SSL_CTX* ctx);
SSL_CTX* setup_client(void);
SSL* connect_to_server(SSL_CTX* ctx);
void do_something(SSL* ssl);
#endif
