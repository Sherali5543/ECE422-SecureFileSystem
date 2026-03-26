#include <stdlib.h>

#include "tls.h"

#define DEFAULT_CA_CERT "server/deploy/secrets/server-cert.pem"
#define DEFAULT_SERVER_ADDR "localhost"
#define DEFAULT_SERVER_PORT "8443"

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
  if (ca_cert == NULL || ca_cert[0] == '\0') {
    ca_cert = DEFAULT_CA_CERT;
  }
  return tls_client_config(ca_cert);
}

SSL* connect_to_server(SSL_CTX* ctx) {
  const char* server_addr = getenv("SERVER_ADDR");
  const char* server_port = getenv("SERVER_PORT");
  if (server_addr == NULL || server_addr[0] == '\0') {
    server_addr = DEFAULT_SERVER_ADDR;
  }
  if (server_port == NULL || server_port[0] == '\0') {
    server_port = DEFAULT_SERVER_PORT;
  }
  return tls_client_connect(ctx, server_addr, server_port);
}
