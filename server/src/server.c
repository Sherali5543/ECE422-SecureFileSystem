#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "http.h"
#include "routing.h"
#include "server_context.h"
#include "tls.h"

void handle_client(SSL* ssl, server_context_t *ctx) {
  while (1) {
    printf("---------Reading request\n");
    http_message_t* msg = read_request(ssl);
    if (msg == NULL) {
      printf("No message\n");
      return;
    }

    printf("-------Handling request\n");
    http_message_t* response = handle_request(msg, ssl, ctx);
    free(msg);
    if (response == NULL) {
      printf("No response\n");
      return;  // Shouldn't actually happen
    }
    printf("---------Sending response\n");
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
      printf("Error closing\n");
    }
    SSL_free(ssl);
  }

  db_cleanup(&server_ctx);
  tls_cleanup(ctx, abio);
}
