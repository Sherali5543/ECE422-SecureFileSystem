#include "storage.h"

#include <string.h>

int storage_read_file(server_context_t* ctx, const http_message_t* request,
                      http_message_t* response) {
  (void)ctx;
  (void)request;

  response->status_code = 501;
  strncpy(response->reason, "Not Implemented", sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  strncpy(response->content_type, "application/json",
          sizeof(response->content_type) - 1);
  response->content_type[sizeof(response->content_type) - 1] = '\0';
  strncpy((char*)response->body,
          "{\"error\":\"read handler not implemented\"}",
          sizeof(response->body) - 1);
  response->body_len = strlen((char*)response->body);
  response->content_length = response->body_len;
  return 0;
}

int storage_write_file(server_context_t* ctx, const http_message_t* request,
                       http_message_t* response) {
  (void)ctx;
  (void)request;

  response->status_code = 501;
  strncpy(response->reason, "Not Implemented", sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  strncpy(response->content_type, "application/json",
          sizeof(response->content_type) - 1);
  response->content_type[sizeof(response->content_type) - 1] = '\0';
  strncpy((char*)response->body,
          "{\"error\":\"write handler not implemented\"}",
          sizeof(response->body) - 1);
  response->body_len = strlen((char*)response->body);
  response->content_length = response->body_len;
  return 0;
}
