#include <stdlib.h>

#include "tls.h"

void disconnect_server(SSL* ssl, SSL_CTX* ctx) {
  int ret = SSL_shutdown(ssl);
  if (ret < 0) {
    printf("Error closing\n");
  }
  SSL_free(ssl);
  tls_cleanup(ctx, NULL);
}

SSL_CTX* setup_client(void) {
  const char* ca_cert = getenv("CA_CERT");
  return tls_client_config(ca_cert);
}

SSL* connect_to_server(SSL_CTX* ctx) {
  const char* server_addr = getenv("SERVER_ADDR");
  const char* server_port = getenv("SERVER_PORT");
  return tls_client_connect(ctx, server_addr, server_port);
}
