#include "http.h"
#include "tls.h"

// Replace this with whatever
void handle_client(SSL* ssl) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;
  if (http_init_contex(&ctx) != 0) {
    return;
  }
  http_parser_init(&parser, &settings, REQUEST);
  char buf[HTTP_MAX_PREAMBLE_LEN];
  size_t total = 0;
  ssize_t nread = 0, nwritten = 0;
  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) break;
    read_status = http_parse_message(buf, (size_t)nread, &parser, &ctx);
  }
  printf("method = %d\n", ctx.msg->method );
  printf("path = [%s]\n", ctx.msg->path);
  printf("query = [%s]\n", ctx.msg->query);
  printf("content_type = [%s]\n", ctx.msg->content_type);
  printf("content_length = %zu\n", ctx.msg->content_length);
  printf("connection = [%s]\n", ctx.msg->connection);
  printf("auth = [%s]\n", ctx.msg->auth_token);
  printf("Status code = %d\n", ctx.msg->status_code);
  memset(buf, 0, sizeof(buf));
  ctx.msg->status_code = 200;
  http_build_header(ctx.msg, buf, RESPONSE, NONE);
  nwritten = tls_write(ssl, buf, (size_t)nread);
  if (nwritten <= 0) return;
  total += (size_t)nwritten;
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
    if (ret < 0) {
      printf("Error closing\n");
    }
    SSL_free(ssl);
  }
  tls_cleanup(ctx, abio);
}
