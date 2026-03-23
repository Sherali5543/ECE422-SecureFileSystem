#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>

#include "tls.h"

// Example handler 
// Sends get http request 
// Server echos back. In actual code would not use total but with content length
void do_something(SSL* ssl) {
  const char* server_addr = getenv("SERVER_ADDR");
  const char* request_start = "GET / HTTP/1.0\r\nConnection: close\r\nHost: ";
  const char* request_end = "\r\n\r\n";

  ssize_t nwritten = 0;
  size_t total = 0;

  nwritten = tls_write(ssl, (void*)request_start, strlen(request_start));
  total += (size_t)nwritten;
  if ((size_t)nwritten != strlen(request_start)) {
    printf("Error writing\n");
    return;
  }

  nwritten = tls_write(ssl, (void*)server_addr, strlen(server_addr));
  total += (size_t)nwritten;
  if ((size_t)nwritten != strlen(server_addr)) {
    printf("Error writing\n");
    return;
  }

  nwritten = tls_write(ssl, (void*)request_end, strlen(request_end));
  total += (size_t)nwritten;
  if ((size_t)nwritten != strlen(request_end)) {
    printf("Error writing\n");
    return;
  }

  char buf[160];
  size_t received = 0;

  while (received < total) {
    size_t want = total - received;
    if (want > sizeof(buf)) want = sizeof(buf);

    ssize_t nread = tls_read(ssl, buf, want);
    if (nread < 0) {
      printf("Error reading\n");
      return;
    }
    if (nread == 0) {
      printf("Unexpected EOF\n");
      return;
    }

    fwrite(buf, 1, (size_t)nread, stdout);
    received += (size_t)nread;
  }

  printf("\n");
}

void connect_to_server(void) {
  const char* ca_cert = getenv("CA_CERT");
  const char* server_addr = getenv("SERVER_ADDR");
  const char* server_port = getenv("SERVER_PORT");

  SSL_CTX* ctx = tls_client_config(ca_cert);
  SSL* ssl = tls_client_connect(ctx, server_addr, server_port);

  do_something(ssl);

  int ret = SSL_shutdown(ssl);
  if (ret < 0) {
    printf("Error closing\n");
  }
  SSL_free(ssl);
  tls_cleanup(ctx, NULL);
}
