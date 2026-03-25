#ifndef HTTP_H
#define HTTP_H
#include <sys/types.h>

#include "llhttp.h"

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
#define HTTP_MAX_START_LEN                                        \
  (HTTP_MAX_METHOD_LEN + HTTP_MAX_PATH_LEN + HTTP_MAX_QUERY_LEN + \
   HTTP_MAX_VERSION_LEN)
#define HTTP_MAX_HEADER_LEN (HTTP_MAX_HEADER_NAME + HTTP_MAX_HEADER_VALUE)
#define HTTP_MAX_PREAMBLE_LEN (HTTP_MAX_START_LEN + HTTP_MAX_HEADER_LEN * 5 + 2)

typedef enum {
  UNKNOWN = 0,
  GET,
  POST,
  PUT,
  PATCH,
  DELETE,
} http_method_t;

typedef enum { NONE = 0, JSON, STREAM } http_content_type_t;

typedef enum { REQUEST = 0, RESPONSE } http_message_type_t;

// This is your friendly message struct
typedef struct {
  http_method_t method;
  http_message_type_t type;
  char path[HTTP_MAX_PATH_LEN];
  char query[HTTP_MAX_QUERY_LEN];
  char reason[HTTP_MAX_QUERY_LEN];

  int status_code;

  char content_type[HTTP_MAX_HEADER_VALUE];
  size_t content_length;
  char connection[HTTP_MAX_HEADER_VALUE];
  char auth_token[HTTP_MAX_TOKEN_LEN];

  uint8_t body[HTTP_MAX_BODY_LEN];
  size_t body_len;

} http_message_t;

typedef enum {
  HTTP_HDR_NONE = 0,
  HTTP_HDR_FIELD,
  HTTP_HDR_VALUE
} http_header_state_t;

typedef enum {
  HTTP_READ_ERROR = -1,
  HTTP_READ_NEED_MORE = 0,
  HTTP_READ_HEADERS_COMPLETE = 1
} http_read_status_t;

// Internal struct to handle broken messages
typedef struct {
  http_message_t* msg;

  char url[HTTP_MAX_QUERY_LEN];
  size_t current_url_len;

  char current_header_name[HTTP_MAX_HEADER_NAME];
  size_t current_header_name_len;

  char current_header_value[HTTP_MAX_HEADER_VALUE];
  size_t current_header_value_len;

  http_header_state_t header_state;

  int message_complete;
} http_parse_ctx_t;

/*
 * @brief Init context object
 *
 * @param ctx Context object
 *
 * @return int error code. -1 if fail 0 if success
 */
int http_init_context(http_parse_ctx_t* ctx);

/*
 * @brief Setup the http parser, required before calling any other function
 *
 * Parser should live for the lifetime of your http session hence why it is
 * passed in rather than created
 *
 * @param parser HTTP parser object
 * @param settings HTTP settings object
 * @param type Enum RESPONSE or REQUEST specifying the type of http message
 *
 */
void http_parser_init(llhttp_t* parser, llhttp_settings_t* settings,
                      http_message_type_t type);
/*
 * @brief Allocates memory for message struct
 *
 * Pass this into memory attribute of context struct
 *
 * @return http_message_t * Pointer to allocated message object
 */
http_message_t* init_message_struct(void);

/*
 * @brief parses the buffer and extracts HTTP header
 *
 * HTTP messages may arrive broken so depending on return value you will need to
 * continue call this as packets arrive
 *
 * @param buf Buffer containing HTTP message
 * @param len Len of buffer
 * @param parser Initialized parser
 * @param ctx Initialized context
 *
 * @return http_read_status_t Enum on state of read. Possible values:
 *          HTTP_READ_ERROR - Error in parsing
 *          HTTP_READ_NEED_MORE - Incomplete message, call as new packets arrive
 *          HTTP_READ_HEADERS_COMPLETE - Headers complete
 */
http_read_status_t http_parse_message(char* buf, size_t len, llhttp_t* parser,
                                      http_parse_ctx_t* ctx);

/*
 * @brief Builds the http header from a http_message_t object
 *
 * @param msg Message struct holding http metadata
 * @param out Output buffer assumed size of HTTP_MAX_PREAMBLE_LEN
 * @param type Enum type of message REQUEST or RESPONSE
 * @param content_type Enum type of body NONE, JSON, or STREAM
 *
 * @return int Status code -1 fail N bytes for size written success
 */
ssize_t http_build_header(const http_message_t* msg,
                          char out[HTTP_MAX_PREAMBLE_LEN],
                          http_message_type_t type,
                          http_content_type_t content_type);

/* Request syntax
 * METHOD PATH?QUERY HTTP/1.1
 * Authorization: Bearer <token>
 * Content-type      // MIME type
 * Content-length
 * Content-encoding  // Necessary for file requests
 * Connection: [keep-alive|close]
 *
 * BODY              // Body termination determined via data type
 */

/* Response syntax
 * HTTP/1.1 CODE REASON/PHRASE
 * Content-length
 * Content-type
 * Connection
 *
 * BODY // Same as what client sent
 */
#endif
