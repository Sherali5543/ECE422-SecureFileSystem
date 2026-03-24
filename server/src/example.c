#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http.h"

int test(void) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.msg = init_message_struct();
  if (!ctx.msg) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }

  http_parser_init(&parser, &settings, RESPONSE);

  // char req[] =
  //     "GET /files?path=/home/user/docs HTTP/1.1\r\n"
  //     "Host: example.com\r\n"
  //     "Content-Type: application/json\r\n"
  //     "Content-Length: 0\r\n"
  //     "Connection: keep-alive\r\n"
  //     "Authorization: Bearer abc123\r\n"
  //     "\r\n";
  char* req =
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: application/json\r\n"
      "Content-Length: 17\r\n"
      "Connection: close\r\n"
      "\r\n"
      "{\"ok\":true}\n";

  http_read_status_t st = http_parse_message(req, strlen(req), &parser, &ctx);

  printf("status = %d\n", st);
  printf("method = %d\n", ctx.msg->method == RESPONSE);
  printf("path = [%s]\n", ctx.msg->path);
  printf("query = [%s]\n", ctx.msg->query);
  printf("content_type = [%s]\n", ctx.msg->content_type);
  printf("content_length = %zu\n", ctx.msg->content_length);
  printf("connection = [%s]\n", ctx.msg->connection);
  printf("auth = [%s]\n", ctx.msg->auth_token);
  printf("Status code = %d\n", llhttp_get_status_code(&parser));
  printf("Status code = %d\n", llhttp_get_status_code(&parser) != 0);

  llhttp_t parser2;
  llhttp_settings_t settings2;
  http_parse_ctx_t ctx2;

  memset(&ctx2, 0, sizeof(ctx2));
  ctx2.msg = init_message_struct();
  if (!ctx2.msg) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }

  http_parser_init(&parser2, &settings2, REQUEST);

  char p1[] = "GET /files?path=/home/user/docs HTTP/1.1\r\nCon";
  char p2[] = "tent-Type: application/json\r\nAuthoriz";
  char p3[] = "ation: Bearer abc123\r\nConnection: keep-alive\r\n\r\n";

  st = http_parse_message(p1, strlen(p1), &parser2, &ctx2);
  printf("st1 = %d\n", st);
  printf("status = %d\n", st);
  printf("method = %d\n", ctx2.msg->method);
  printf("path = [%s]\n", ctx2.msg->path);
  printf("query = [%s]\n", ctx2.msg->query);
  printf("content_type = [%s]\n", ctx2.msg->content_type);
  printf("content_length = %zu\n", ctx2.msg->content_length);
  printf("connection = [%s]\n", ctx2.msg->connection);
  printf("auth = [%s]\n", ctx2.msg->auth_token);

  st = http_parse_message(p2, strlen(p2), &parser2, &ctx2);
  printf("st2 = %d\n", st);
  printf("status = %d\n", st);
  printf("method = %d\n", ctx2.msg->method);
  printf("path = [%s]\n", ctx2.msg->path);
  printf("query = [%s]\n", ctx2.msg->query);
  printf("content_type = [%s]\n", ctx2.msg->content_type);
  printf("content_length = %zu\n", ctx2.msg->content_length);
  printf("connection = [%s]\n", ctx2.msg->connection);
  printf("auth = [%s]\n", ctx2.msg->auth_token);

  st = http_parse_message(p3, strlen(p3), &parser2, &ctx2);
  printf("st3 = %d\n", st);
  printf("status = %d\n", st);
  printf("method = %d\n", ctx2.msg->method == GET);
  printf("path = [%s]\n", ctx2.msg->path);
  printf("query = [%s]\n", ctx2.msg->query);
  printf("content_type = [%s]\n", ctx2.msg->content_type);
  printf("content_length = %zu\n", ctx2.msg->content_length);
  printf("connection = [%s]\n", ctx2.msg->connection);
  printf("auth = [%s]\n", ctx2.msg->auth_token);
  printf("Status code = %d\n", llhttp_get_status_code(&parser2));

  http_message_t test_message = *ctx2.msg;
  char out[HTTP_MAX_START_LEN + HTTP_MAX_HEADER_LEN * 5];
  http_build_header(&test_message, out, REQUEST, NONE);
  llhttp_t parser3;
  llhttp_settings_t settings3;
  http_parse_ctx_t ctx3;

  memset(&ctx3, 0, sizeof(ctx3));
  ctx3.msg = init_message_struct();
  if (!ctx3.msg) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }

  http_parser_init(&parser3, &settings3, REQUEST);
  st = http_parse_message(out, strlen(out), &parser3, &ctx3);
  printf("st3 = %d\n", st);
  printf("status = %d\n", st);
  printf("method = %d\n", ctx3.msg->method == GET);
  printf("path = [%s]\n", ctx3.msg->path);
  printf("query = [%s]\n", ctx3.msg->query);
  printf("content_type = [%s]\n", ctx3.msg->content_type);
  printf("content_length = %zu\n", ctx3.msg->content_length);
  printf("connection = [%s]\n", ctx3.msg->connection);
  printf("auth = [%s]\n", ctx3.msg->auth_token);
  printf("Status code = %d\n", llhttp_get_status_code(&parser3));


  http_message_t test_message2 = *ctx.msg;
  char out2[HTTP_MAX_START_LEN + HTTP_MAX_HEADER_LEN * 5];
  http_build_header(&test_message2, out2, RESPONSE, NONE);
  llhttp_t parser4;
  llhttp_settings_t settings4;
  http_parse_ctx_t ctx4;

  memset(&ctx4, 0, sizeof(ctx4));
  ctx4.msg = init_message_struct();
  if (!ctx4.msg) {
    fprintf(stderr, "alloc failed\n");
    return 1;
  }

  http_parser_init(&parser4, &settings4, RESPONSE);
  st = http_parse_message(out2, strlen(out2), &parser4, &ctx4);
  printf("st4 = %d\n", st);
  printf("status = %d\n", st);
  printf("method = %d\n", ctx4.msg->method == GET);
  printf("path = [%s]\n", ctx4.msg->path);
  printf("query = [%s]\n", ctx4.msg->query);
  printf("content_type = [%s]\n", ctx4.msg->content_type);
  printf("content_length = %zu\n", ctx4.msg->content_length);
  printf("connection = [%s]\n", ctx4.msg->connection);
  printf("auth = [%s]\n", ctx4.msg->auth_token);
  printf("Status code = %d\n", llhttp_get_status_code(&parser4));
  return 0;
}
