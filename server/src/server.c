#include "tls.h"

// Replace this with whatever
void handle_client(SSL* ssl) {
  char buf[4096];
  size_t total = 0;
  while (1) {
    ssize_t nread = 0, nwritten = 0;
    nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) break;
    nwritten = tls_write(ssl, buf, (size_t)nread);
    if (nwritten <= 0) break;
    total += (size_t)nwritten;
  }
  fprintf(stderr, "Client connection closed %zu bytes sent\n", total);
}

void server_loop(void) {
  const char* cert = getenv("SERVER_CERT");
  const char* key = getenv("SERVER_KEY");
  const char* port = getenv("PORT");
  SSL_CTX* ctx = tls_server_config(cert, key);
  BIO* abio = tls_server_init(ctx, port);
  while (1) {
    SSL* ssl = tls_server_accept(ctx, abio);
    if (ssl == NULL) continue;

    // handle client
    handle_client(ssl);
    int ret = SSL_shutdown(ssl);
    if (ret < 0){
      printf("Error closing\n");
    }
    SSL_free(ssl);
  }
  tls_cleanup(ctx, abio);
}
