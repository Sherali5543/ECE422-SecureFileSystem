#include "http.h"
#include "tls.h"
#include "routing.h"

// Just here for testing
void test_read_message_contents(http_parse_ctx_t ctx) {
  printf("method = %d\n", ctx.msg->method);
  printf("path = [%s]\n", ctx.msg->path);
  printf("query = [%s]\n", ctx.msg->query);
  printf("content_type = [%s]\n", ctx.msg->content_type);
  printf("content_length = %zu\n", ctx.msg->content_length);
  printf("connection = [%s]\n", ctx.msg->connection);
  printf("auth = [%s]\n", ctx.msg->auth_token);
  printf("Status code = %d\n", ctx.msg->status_code);
}

http_message_t* read_request(SSL* ssl) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;
  if (http_init_context(&ctx) != 0) {
    printf("early return");
    return NULL;
  }
  http_parser_init(&parser, &settings, REQUEST);

  char buf[HTTP_MAX_PREAMBLE_LEN];
  memset(buf, 0, sizeof(buf));
  ssize_t nread = 0;
  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) break;
    read_status = http_parse_message(buf, (size_t)nread, &parser, &ctx);
  }

  test_read_message_contents(ctx);
  memset(buf, 0, sizeof(buf));

  return ctx.msg;
}

void send_response(SSL* ssl, http_message_t *response){
  char buf[HTTP_MAX_PREAMBLE_LEN];
  memset(buf, 0, HTTP_MAX_PREAMBLE_LEN);
  ssize_t header_len = http_build_header(response, buf, RESPONSE, JSON);
  if (header_len < 0) return;
  ssize_t nwritten = tls_write(ssl, buf, (size_t)header_len);
  if (nwritten <= 0) return;
  fprintf(stderr, "Client connection closed %zu bytes sent\n", nwritten);
}

// Replace this with whatever
void handle_client(SSL* ssl) {
  printf("Reading request\n");
  http_message_t* msg = read_request(ssl);

  printf("Handling request\n");
  http_message_t* response = handle_request(msg);
  free(msg); 
  if(response == NULL){
    printf("No response\n");
    return; // Shouldn't actually happen
  }
  printf("Sending response\n");
  send_response(ssl, response);
  clean_response(response);
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
