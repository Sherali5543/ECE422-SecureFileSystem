#include "llhttp.h"
#include "tls.h"

#define HTTP_MAX_METHOD_LEN 16
#define HTTP_MAX_PATH_LEN 256
#define HTTP_MAX_QUERY_LEN 2048
#define HTTP_MAX_VERSION_LEN 16
#define HTTP_MAX_HEADER_NAME 64
#define HTTP_MAX_HEADER_VALUE 1024
#define HTTP_MAX_HEADERS 32
#define HTTP_MAX_TOKEN_LEN 256
#define HTTP_MAX_CONTENT_TYPE 128
#define HTTP_MAX_BODY_LEN 8192

typedef enum {
  UNKNOWN,
  GET,
  POST,
  PUT,
  DELETE,
} http_method_t;

typedef struct {
  http_method_t method;
  char path[HTTP_MAX_PATH_LEN];
  char content_type[HTTP_MAX_HEADER_VALUE];
  size_t content_length;
  char connection[HTTP_MAX_HEADER_VALUE];
  uint8_t body[HTTP_MAX_BODY_LEN];
  size_t body_len;

} http_message_t;

typedef enum {
    HTTP_HDR_NONE = 0,
    HTTP_HDR_FIELD,
    HTTP_HDR_VALUE
} http_header_state_t;

typedef struct {
  http_message_t msg;

  char current_header_name[HTTP_MAX_HEADER_NAME];
  size_t current_header_name_len;

  char current_header_value[HTTP_MAX_HEADER_VALUE];
  size_t current_header_value_len;

  http_header_state_t header_state;

  int message_complete;
} http_parse_ctx_t;

http_message_t http_read();
http_message_t http_read_body();
void http_send_message();
void http_stream_body();

/* parse full raw message at once */
int http_parse_message(const char *raw, size_t raw_len, http_message_t *msg);

/* optional streaming-style commit helper */
int http_commit_header(http_parse_ctx_t *ctx);

/* build raw HTTP text from struct */
int http_build_message(const http_message_t *msg, char *out, size_t out_sz);

