#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "http.h"
#include "routing.h"
#include "server_context.h"
#include "tls.h"

#define DEFAULT_SERVER_CERT "server/deploy/secrets/server-cert.pem"
#define DEFAULT_SERVER_KEY "server/deploy/secrets/server-key.pem"
#define DEFAULT_SERVER_PORT "8443"

void handle_client(SSL* ssl, server_context_t *ctx) {
  while (1) {
    http_message_t* msg = read_request(ssl);
    if (msg == NULL) {
      return;
    }

    http_message_t* response = handle_request(msg, ssl, ctx);
    free(msg);
    if (response == NULL) {
      return;  // Shouldn't actually happen
    }
    if (!response->message_sent) {
      send_response(ssl, response);
    }
    destroy_message(response);
  }
}

void server_loop(void) {
  const char* cert = getenv("SERVER_CERT");
  const char* key = getenv("SERVER_KEY");
  const char* port = getenv("PORT");
  server_context_t server_ctx;

  if (cert == NULL || cert[0] == '\0') {
    cert = DEFAULT_SERVER_CERT;
  }
  if (key == NULL || key[0] == '\0') {
    key = DEFAULT_SERVER_KEY;
  }
  if (port == NULL || port[0] == '\0') {
    port = DEFAULT_SERVER_PORT;
  }

  if (server_context_init(&server_ctx) != 0) {
    fprintf(stderr, "Failed to initialize server context\n");
    return;
  }
  if (db_init(&server_ctx) != 0) {
    fprintf(stderr, "Failed to initialize database layer\n");
    return;
  }

  SSL_CTX* ctx = tls_server_config(cert, key);
  BIO* abio = tls_server_init(ctx, port);
  while (1) {
    SSL* ssl = tls_server_accept(ctx, abio);
    if (ssl == NULL) continue;

    // handle client
    handle_client(ssl, &server_ctx);
    int ret = SSL_shutdown(ssl);
    if (ret < 0) {
      fprintf(stderr, "Error closing TLS connection\n");
    }
    SSL_free(ssl);
  }

  db_cleanup(&server_ctx);
  tls_cleanup(ctx, abio);
}
