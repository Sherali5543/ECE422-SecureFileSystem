#include <stdlib.h>
#include <string.h>

#include "http.h"

static size_t consume_prefetched_body(http_message_t* msg, void* buf,
                                      size_t len) {
  size_t take = 0;

  if (msg == NULL || buf == NULL || len == 0 || msg->body_prefix_len == 0) {
    return 0;
  }

  take = len;
  if (take > msg->body_prefix_len) {
    take = msg->body_prefix_len;
  }

  memcpy(buf, msg->body_prefix, take);
  if (take < msg->body_prefix_len) {
    memmove(msg->body_prefix, msg->body_prefix + take,
            msg->body_prefix_len - take);
  }
  msg->body_prefix_len -= take;
  return take;
}

int drain_body(SSL* ssl, size_t len) {
  char buf[1024];
  size_t total = 0;

  while (total < len) {
    size_t want = len - total;
    if (want > sizeof(buf)) want = sizeof(buf);

    ssize_t n = tls_read(ssl, buf, want);
    if (n <= 0) return -1;

    total += (size_t)n;
  }

  return 0;
}

int drain_message_body(SSL* ssl, http_message_t* msg, size_t len) {
  size_t consumed = 0;

  if (msg != NULL && msg->body_prefix_len > 0) {
    consumed = len;
    if (consumed > msg->body_prefix_len) {
      consumed = msg->body_prefix_len;
    }

    if (consumed < msg->body_prefix_len) {
      memmove(msg->body_prefix, msg->body_prefix + consumed,
              msg->body_prefix_len - consumed);
    }
    msg->body_prefix_len -= consumed;
    len -= consumed;
  }

  if (len == 0) {
    return 0;
  }

  return drain_body(ssl, len);
}

ssize_t read_message_body(SSL* ssl, http_message_t* msg, void* buf, size_t len) {
  size_t total = 0;

  if (ssl == NULL || msg == NULL || buf == NULL) {
    return -1;
  }

  total += consume_prefetched_body(msg, buf, len);
  while (total < len) {
    ssize_t n = tls_read(ssl, (unsigned char*)buf + total, len - total);
    if (n <= 0) {
      return -1;
    }
    total += (size_t)n;
  }

  return (ssize_t)total;
}

http_message_t* init_request(void) {
  http_message_t* msg = malloc(sizeof(http_message_t));
  memset(msg, 0, sizeof(http_message_t));
  msg->type = REQUEST;
  msg->method = UNKNOWN;
  msg->content_type = NONE;
  strncpy(msg->path, "/", sizeof(msg->path));
  strncpy(msg->connection, "keep-alive", sizeof(msg->connection));
  return msg;
}

http_message_t* init_response(void) {
  http_message_t* msg = malloc(sizeof(http_message_t));
  memset(msg, 0, sizeof(http_message_t));
  msg->type = RESPONSE;
  msg->status_code = 400;
  msg->content_type = NONE;
  strncpy(msg->reason, "Bad command", sizeof(msg->reason));
  strncpy(msg->connection, "close", sizeof(msg->connection));
  return msg;
}

void destroy_message(http_message_t* msg) { free(msg); }

http_message_t* read_request(SSL* ssl) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;
  if (http_init_context(&ctx) != 0) {
    return NULL;
  }
  http_parser_init(&parser, &settings, REQUEST);

  char buf[1];
  memset(buf, 0, sizeof(buf));
  ssize_t nread = 0;
  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) {
      destroy_message(ctx.msg);
      return NULL;
    }
    read_status = http_parse_message(buf, (size_t)nread, &parser, &ctx);
  }

  memset(buf, 0, sizeof(buf));
  if (read_status != HTTP_READ_HEADERS_COMPLETE) {
    destroy_message(ctx.msg);
    return NULL;
  }
  return ctx.msg;
}

http_message_t* read_response(SSL* ssl) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t ctx;
  if (http_init_context(&ctx) != 0) {
    return NULL;
  }
  http_parser_init(&parser, &settings, RESPONSE);

  char buf[1];
  memset(buf, 0, sizeof(buf));
  ssize_t nread = 0;
  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) {
      destroy_message(ctx.msg);
      return NULL;
    }
    read_status = http_parse_message(buf, (size_t)nread, &parser, &ctx);
  }
  memset(buf, 0, sizeof(buf));
  if (read_status != HTTP_READ_HEADERS_COMPLETE) {
    destroy_message(ctx.msg);
    return NULL;
  }

  return ctx.msg;
}

void send_response(SSL* ssl, http_message_t* response) {
  char buf[HTTP_MAX_PREAMBLE_LEN];
  memset(buf, 0, HTTP_MAX_PREAMBLE_LEN);
  ssize_t header_len = http_build_header(response, buf, RESPONSE);
  if (header_len < 0) return;
  ssize_t nwritten = tls_write(ssl, buf, (size_t)header_len);
  if (nwritten <= 0) return;
  response->message_sent = true;
}

void send_request(SSL* ssl, http_message_t* response) {
  char buf[HTTP_MAX_PREAMBLE_LEN];
  memset(buf, 0, HTTP_MAX_PREAMBLE_LEN);
  ssize_t header_len = http_build_header(response, buf, REQUEST);
  if (header_len < 0) return;
  ssize_t nwritten = tls_write(ssl, buf, (size_t)header_len);
  if (nwritten <= 0) return;
  response->message_sent = true;
}
