#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"
#include "http.h"
#include "routes.h"
#include "server_context.h"
#include "tls.h"

static void init_response(http_message_t* response) {
  memset(response, 0, sizeof(*response));
  response->type = RESPONSE;
  response->status_code = 500;
  strncpy(response->reason, "Internal Server Error",
          sizeof(response->reason) - 1);
  strncpy(response->connection, "close", sizeof(response->connection) - 1);
}

static int write_response(SSL* ssl, const http_message_t* response) {
  char header[HTTP_MAX_PREAMBLE_LEN];
  size_t total = 0;
  ssize_t header_len = 0;
  ssize_t nwritten = 0;

  memset(header, 0, sizeof(header));
  header_len = http_build_header(response, header, RESPONSE, JSON);
  if (header_len < 0) {
    return -1;
  }

  nwritten = tls_write(ssl, header, (size_t)header_len);
  if (nwritten <= 0) {
    return -1;
  }
  total += (size_t)nwritten;

  if (response->body_len > 0) {
    nwritten = tls_write(ssl, (void*)response->body, response->body_len);
    if (nwritten <= 0) {
      return -1;
    }
    total += (size_t)nwritten;
  }

  fprintf(stderr, "Client connection closed %zu bytes sent\n", total);
  return 0;
}

static int read_request_body(SSL* ssl, http_parse_ctx_t* request_ctx, char* buf,
                             size_t initial_bytes, size_t initial_body_offset) {
  http_message_t* request = request_ctx->msg;
  if (request == NULL) {
    return -1;
  }

  if (request->content_length >= sizeof(request->body)) {
    fprintf(stderr, "Request body too large: %zu bytes\n",
            request->content_length);
    return -1;
  }

  request->body_len = 0;
  if (initial_body_offset < initial_bytes) {
    size_t buffered_body_bytes = initial_bytes - initial_body_offset;
    if (buffered_body_bytes > request->content_length) {
      buffered_body_bytes = request->content_length;
    }

    memcpy(request->body, buf + initial_body_offset, buffered_body_bytes);
    request->body_len = buffered_body_bytes;
  }

  while (request->body_len < request->content_length) {
    size_t remaining = request->content_length - request->body_len;
    if (remaining > HTTP_MAX_PREAMBLE_LEN) {
      remaining = HTTP_MAX_PREAMBLE_LEN;
    }

    ssize_t nread = tls_read(ssl, buf, remaining);
    if (nread <= 0) {
      return -1;
    }

    memcpy(request->body + request->body_len, buf, (size_t)nread);
    request->body_len += (size_t)nread;
  }

  request->body[request->body_len] = '\0';
  return 0;
}

static void handle_client(SSL* ssl, server_context_t* server_ctx) {
  llhttp_t parser;
  llhttp_settings_t settings;
  http_parse_ctx_t request_ctx;
  http_message_t response;
  char buf[HTTP_MAX_PREAMBLE_LEN];
  size_t last_nread = 0;

  if (http_init_context(&request_ctx) != 0) {
    return;
  }

  init_response(&response);
  http_parser_init(&parser, &settings, REQUEST);

  http_read_status_t read_status = HTTP_READ_NEED_MORE;
  while (read_status == HTTP_READ_NEED_MORE) {
    ssize_t nread = tls_read(ssl, buf, sizeof(buf));
    if (nread <= 0) {
      free(request_ctx.msg);
      return;
    }
    last_nread = (size_t)nread;
    read_status = http_parse_message(buf, (size_t)nread, &parser, &request_ctx);
  }

  if (read_status == HTTP_READ_ERROR) {
    response.status_code = 400;
    strncpy(response.reason, "Bad Request", sizeof(response.reason) - 1);
    strncpy((char*)response.body, "{\"error\":\"failed to parse request\"}",
            sizeof(response.body) - 1);
    response.body_len = strlen((char*)response.body);
    response.content_length = response.body_len;
  } else {
    if (request_ctx.msg->content_length > 0 &&
        read_request_body(ssl, &request_ctx, buf, last_nread,
                          request_ctx.parsed_bytes) != 0) {
      response.status_code = 400;
      strncpy(response.reason, "Bad Request", sizeof(response.reason) - 1);
      strncpy((char*)response.body, "{\"error\":\"failed to read request body\"}",
              sizeof(response.body) - 1);
      response.body_len = strlen((char*)response.body);
      response.content_length = response.body_len;
      write_response(ssl, &response);
      free(request_ctx.msg);
      return;
    }
    route_request(server_ctx, request_ctx.msg, &response);
  }

  write_response(ssl, &response);
  free(request_ctx.msg);
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
    if (ssl == NULL) {
      continue;
    }

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
