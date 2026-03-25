#include "http.h"
#include "routing.h"
#include "tls.h"

void handle_client(SSL* ssl) {
  while (1) {
    printf("---------Reading request\n");
    http_message_t* msg = read_request(ssl);
    if(msg == NULL){
      printf("No message\n");
      return;
    }

    printf("-------Handling request\n");
    http_message_t* response = handle_request(msg, ssl);
    free(msg);
    if (response == NULL) {
      printf("No response\n");
      return;  // Shouldn't actually happen
    }
    printf("---------Sending response\n");
    send_response(ssl, response);
    destroy_message(response);
  }
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
    if (ret < 0) {
      printf("Error closing\n");
    }
    SSL_free(ssl);
  }
  tls_cleanup(ctx, abio);
}
