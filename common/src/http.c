#include "http.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int commit_header(llhttp_t* parser) {
  http_parse_ctx_t* data = parser->data;
  assert(data->header_state == HTTP_HDR_VALUE);

  if (strcasecmp(data->current_header_name, "Content-Type") == 0) {
    strncpy(data->msg->content_type, data->current_header_value,
            sizeof(data->msg->content_type) - 1);
    data->msg->content_type[sizeof(data->msg->content_type) - 1] = '\0';
  } else if (strcasecmp(data->current_header_name, "Content-Length") == 0) {
    data->msg->content_length =
        (size_t)strtol(data->current_header_value, NULL, 10);
  } else if (strcasecmp(data->current_header_name, "Connection") == 0) {
    strncpy(data->msg->connection, data->current_header_value,
            sizeof(data->msg->connection) - 1);
    data->msg->connection[sizeof(data->msg->connection) - 1] = '\0';
  } else if (strcasecmp(data->current_header_name, "Authorization") == 0) {
    strncpy(data->msg->auth_token, data->current_header_value,
            sizeof(data->msg->auth_token) - 1);
    data->msg->auth_token[sizeof(data->msg->auth_token) - 1] = '\0';
  }

  data->current_header_name[0] = '\0';
  data->current_header_value[0] = '\0';
  data->current_header_name_len = 0;
  data->current_header_value_len = 0;
  data->header_state = HTTP_HDR_NONE;

  return 0;
}

static int append_buf(char* dst, size_t* dst_len, size_t cap, const char* src,
                      size_t src_len) {
  if (*dst_len + src_len >= cap) {
    fprintf(stderr, "Append buf: Larger than cap\n");
    return -1;
  }
  memcpy(dst + *dst_len, src, src_len);
  *dst_len += src_len;
  dst[*dst_len] = '\0';
  return 0;
}

static int on_protocol(llhttp_t* parser, const char* at, size_t length) {
  (void)parser;
  (void)length;
  if (strncasecmp("HTTP", at, 4) != 0) {
    fprintf(stderr, "On protocol: Incorrect protocol\n");
    return -1;
  }

  return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
  http_parse_ctx_t* data = parser->data;

  return append_buf(data->url, &data->current_url_len,
                    HTTP_MAX_QUERY_LEN + HTTP_MAX_PATH_LEN, at, length);
}

static int on_version(llhttp_t* parser, const char* at, size_t length) {
  (void)parser;
  (void)length;
  if (strncasecmp("1.1", at, 3) != 0) {
    fprintf(stderr, "On version: Incorrect version\n");
    return -1;
  }

  return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
  http_parse_ctx_t* data = parser->data;

  data->header_state = HTTP_HDR_FIELD;
  return append_buf(data->current_header_name, &data->current_header_name_len,
                    HTTP_MAX_HEADER_NAME, at, length);
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
  http_parse_ctx_t* data = parser->data;
  data->header_state = HTTP_HDR_VALUE;
  return append_buf(data->current_header_value, &data->current_header_value_len,
                    HTTP_MAX_HEADER_VALUE, at, length);
}

static int on_headers_complete(llhttp_t* parser) {
  http_parse_ctx_t* data = parser->data;

  // Method detect
  if (parser->type == HTTP_RESPONSE) {
    data->msg->method = UNKNOWN;
    data->msg->status_code = llhttp_get_status_code(parser);
  } else {
    switch (llhttp_get_method(parser)) {
      case HTTP_GET:
        data->msg->method = GET;
        break;
      case HTTP_POST:
        data->msg->method = POST;
        break;
      case HTTP_PUT:
        data->msg->method = PUT;
        break;
      case HTTP_PATCH:
        data->msg->method = PATCH;
        break;
      case HTTP_DELETE:
        data->msg->method = DELETE;
        break;
      default:
        data->msg->method = UNKNOWN;
        fprintf(stderr, "On method: unknown method\n");
        return -1;
    }
  }

  // Read url
  const char* q = strchr(data->url, '?');

  if (q != NULL) {
    size_t len = (size_t)(q - data->url);
    if (len >= sizeof(data->msg->path)) {
      len = sizeof(data->msg->path) - 1;
    }

    memcpy(data->msg->path, data->url, len);
    data->msg->path[len] = '\0';

    strncpy(data->msg->query, q + 1, sizeof(data->msg->query) - 1);
    data->msg->query[sizeof(data->msg->query) - 1] = '\0';
  } else {
    strncpy(data->msg->path, data->url, sizeof(data->msg->path) - 1);
    data->msg->path[sizeof(data->msg->path) - 1] = '\0';
  }

  return HPE_PAUSED;  // Pause for body processing
}

void http_parser_init(llhttp_t* parser, llhttp_settings_t* settings,
                      http_message_type_t type) {
  llhttp_settings_init(settings);

  settings->on_url = on_url;
  settings->on_header_field = on_header_field;
  settings->on_header_value = on_header_value;
  settings->on_version = on_version;
  settings->on_protocol = on_protocol;
  settings->on_header_value_complete = commit_header;
  settings->on_headers_complete = on_headers_complete;

  llhttp_type_t llhttp_type = HTTP_REQUEST;
  if (type == RESPONSE) {
    llhttp_type = HTTP_RESPONSE;
  }

  llhttp_init(parser, llhttp_type, settings);
}

http_message_t* init_message_struct(void) {
  http_message_t* msg = malloc(sizeof(*msg));
  if (!msg) {
    return NULL;
  }

  memset(msg, 0, sizeof(*msg));
  return msg;
}

http_read_status_t http_parse_message(char* buf, size_t len, llhttp_t* parser,
                                      http_parse_ctx_t* context) {
  parser->data = context;

  enum llhttp_errno err = llhttp_execute(parser, buf, len);

  if (err == HPE_PAUSED) {
    return HTTP_READ_HEADERS_COMPLETE;
  }

  if (err != HPE_OK) {
    fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
            parser->reason ? parser->reason : "");
    return HTTP_READ_ERROR;
  }

  return HTTP_READ_NEED_MORE;
}

static int checklen(const char* str, size_t cap) {
  if (!str || strnlen(str, cap + 1) > cap) {
    printf("String longer than cap\n");
    return 1;
  }

  return 0;
}

ssize_t http_build_header(const http_message_t* msg,
                          char out[HTTP_MAX_PREAMBLE_LEN],
                          http_message_type_t type,
                          http_content_type_t content_type) {
  char start_line[HTTP_MAX_START_LEN];

  if (type == REQUEST) {
    char* method;
    switch (msg->method) {
      case GET:
        method = "GET";
        break;
      case POST:
        method = "POST";
        break;
      case PUT:
        method = "PUT";
        break;
      case PATCH:
        method = "PATCH";
        break;
      case DELETE:
        method = "DELETE";
        break;
      case UNKNOWN:
      default:
        return -1;
    }

    if (strnlen(msg->query, HTTP_MAX_QUERY_LEN) > 0) {
      if (checklen(msg->path, HTTP_MAX_PATH_LEN) ||
          checklen(msg->query, HTTP_MAX_QUERY_LEN))
        return -1;
      snprintf(start_line, HTTP_MAX_START_LEN, "%s %s?%s HTTP/1.1\r\n", method,
               msg->path, msg->query);
    } else {
      if (checklen(msg->path, HTTP_MAX_PATH_LEN)) return -1;
      snprintf(start_line, HTTP_MAX_START_LEN, "%s %s HTTP/1.1\r\n", method,
               msg->path);
    }
  } else {
    if (checklen(msg->reason, HTTP_MAX_QUERY_LEN) || msg->status_code > 999 ||
        msg->status_code < 0)
      return -1;
    snprintf(start_line, HTTP_MAX_START_LEN, "HTTP/1.1 %d %s\r\n",
             msg->status_code, msg->reason);
  }

  // I'm going to assume all headers exist!
  char headers[HTTP_MAX_HEADER_LEN * 5];
  if (checklen(msg->auth_token, HTTP_MAX_HEADER_VALUE) || // Don't check content-length cuz ul >=0
      checklen(msg->connection, HTTP_MAX_HEADER_VALUE))
    return -1;

  int offset = snprintf(headers, sizeof(headers),
                        "Authorization: %s\r\n"
                        "Content-length: %lu\r\n"
                        "Connection: %s\r\n",
                        msg->auth_token, msg->content_length, msg->connection);
  if (offset < 0 || (size_t)offset >= sizeof(headers)) return -1;

  switch (content_type) {
    case JSON:
      snprintf(headers + offset, sizeof(headers) - (size_t)offset,
               "Content-type: application/json\r\n");
      break;
    case STREAM:
      snprintf(headers + offset, sizeof(headers) - (size_t)offset,
               "Content-type: application/octet-stream\r\n");
      break;
    case NONE:
    default:
      break;
  }

  snprintf(out, HTTP_MAX_PREAMBLE_LEN,
           "%s"
           "%s"
           "\r\n",
           start_line, headers);
  return (ssize_t)strlen(out);
}

int http_init_context(http_parse_ctx_t* ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->msg = init_message_struct();
  if (!ctx->msg) {
    fprintf(stderr, "alloc failed\n");
    return -1;
  }

  return 0;
}
