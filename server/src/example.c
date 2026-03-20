#include <stdio.h>
#include <string.h>

#include "llhttp.h"

typedef struct {
  char url[256];
  char current_header_field[128];
  char current_header_value[256];
} parser_data_t;

static int on_message_begin(llhttp_t* parser) {
  printf("message begin\n");
  return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
  parser_data_t* data = (parser_data_t*)parser->data;

  size_t copy_len = length;
  if (copy_len >= sizeof(data->url)) {
    copy_len = sizeof(data->url) - 1;
  }

  memcpy(data->url, at, copy_len);
  data->url[copy_len] = '\0';

  printf("url: %s\n", data->url);
  return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
  parser_data_t* data = (parser_data_t*)parser->data;

  size_t copy_len = length;
  if (copy_len >= sizeof(data->current_header_field)) {
    copy_len = sizeof(data->current_header_field) - 1;
  }

  memcpy(data->current_header_field, at, copy_len);
  data->current_header_field[copy_len] = '\0';

  return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
  parser_data_t* data = (parser_data_t*)parser->data;

  size_t copy_len = length;
  if (copy_len >= sizeof(data->current_header_value)) {
    copy_len = sizeof(data->current_header_value) - 1;
  }

  memcpy(data->current_header_value, at, copy_len);
  data->current_header_value[copy_len] = '\0';

  return 0;
}

static int on_header_value_complete(llhttp_t* parser) {
  parser_data_t* data = (parser_data_t*)parser->data;
  printf("header: %s: %s\n", data->current_header_field,
         data->current_header_value);
  return 0;
}

static int on_headers_complete(llhttp_t* parser) {
  printf("method: %s\n",
         llhttp_method_name((enum llhttp_method)llhttp_get_method(parser)));
  printf("HTTP version: %d.%d\n", llhttp_get_http_major(parser),
         llhttp_get_http_minor(parser));
  return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
  printf("body chunk: %.*s\n", (int)length, at);
  return 0;
}

static int on_message_complete(llhttp_t* parser) {
  printf("message complete\n");
  return 0;
}

int main(void) {
  const char* request =
      "GET /hello?name=shaheer HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "User-Agent: demo-client/1.0\r\n"
      "Accept: */*\r\n"
      "Content-length: 12\r\n"
      "\r\n"
      "example-body";

  llhttp_t parser;
  llhttp_settings_t settings;
  parser_data_t data;

  memset(&data, 0, sizeof(data));
  llhttp_settings_init(&settings);

  settings.on_message_begin = on_message_begin;
  settings.on_url = on_url;
  settings.on_header_field = on_header_field;
  settings.on_header_value = on_header_value;
  settings.on_header_value_complete = on_header_value_complete;
  settings.on_headers_complete = on_headers_complete;
  settings.on_body = on_body;
  settings.on_message_complete = on_message_complete;

  llhttp_init(&parser, HTTP_REQUEST, &settings);
  parser.data = &data;

  enum llhttp_errno err = llhttp_execute(&parser, request, strlen(request));
  if (err != HPE_OK) {
    fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
            parser.reason ? parser.reason : "");
    return 1;
  }

  return 0;
