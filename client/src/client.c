#include <stdlib.h>
#include "http.h"
#include "tls.h"

// Example handler 
// Sends get http request 
// Server echos back. In actual code would not use total but with content length
void do_something(SSL* ssl) {
  http_message_t msg = {
    .method = GET,
    .path = "/",
    .connection = "close",
    .content_length = 0,
    .type = REQUEST
  };

  char buf[HTTP_MAX_PREAMBLE_LEN];
  printf("Building message\n");
  if(http_build_header(&msg, buf, REQUEST, NONE) <= 0){
    printf("ERROR\n");
    return;
  }
  ssize_t nwritten = 0;

  printf("Writing message\n");
  nwritten = tls_write(ssl, (void*)buf, strlen(buf));
  if ((size_t)nwritten != strlen(buf)) {
    printf("Error writing\n");
    return;
  }

  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;
  printf("Init Parser\n");
  if (http_init_context(&ctx) != 0) {
    printf("early return\n");
    return;
  }
  http_parser_init(&parser, &settings, RESPONSE);

  memset(buf, 0, sizeof(buf));
  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    ssize_t nread = tls_read(ssl, buf, sizeof(buf));
    read_status = http_parse_message(buf, sizeof(buf), &parser, &ctx);
    if (nread < 0) {
      printf("Error reading\n");
      return;
    }
    if (nread == 0) {
      printf("Unexpected EOF\n");
      return;
    }

    fwrite(buf, 1, (size_t)nread, stdout);
  }
  printf("method = %d\n", ctx.msg->method );
  printf("path = [%s]\n", ctx.msg->path);
  printf("query = [%s]\n", ctx.msg->query);
  printf("content_type = [%s]\n", ctx.msg->content_type);
  printf("content_length = %zu\n", ctx.msg->content_length);
  printf("connection = [%s]\n", ctx.msg->connection);
  printf("auth = [%s]\n", ctx.msg->auth_token);
  printf("Status code = %d\n", ctx.msg->status_code);

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
