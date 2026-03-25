#include "http.h"
#include "string.h"
#include "routing.h"
#include <stdlib.h>

http_message_t *init_response(void){
  http_message_t *msg = malloc(sizeof(http_message_t));
  memset(msg, 0, sizeof(http_message_t));
  msg->type = RESPONSE;
  msg->status_code = 400;
  msg->content_type = NONE;
  strncpy(msg->reason, "Bad command", sizeof(msg->reason));
  strncpy(msg->connection, "close", sizeof(msg->connection));
  return msg;
}

void clean_response(http_message_t *msg){
  free(msg);
}

http_message_t *handle_request(http_message_t* msg, SSL* ssl) {
  http_message_t *req = init_response();

  switch (msg->method) {
    case GET:
      if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
        // Handle ls/cd files
      } else if (strncmp(msg->path, "/files/contents", HTTP_MAX_PATH_LEN) ==
                 0) {
        // Handle read files
      }
      break;
    case POST:
      if (strncmp(msg->path, "/auth/login", HTTP_MAX_PATH_LEN) == 0) {
        // Handle login
      } else if(strncmp(msg->path, "/auth/register", HTTP_MAX_PATH_LEN) == 0){
        // Handle registration
      } else if(strncmp(msg->path, "/auth/logout", HTTP_MAX_PATH_LEN) == 0){
        // Handle logout
      }else if(strncmp(msg->path, "/files/move", HTTP_MAX_PATH_LEN) == 0){
        // Handle mv
      }else if(strncmp(msg->path, "/directories", HTTP_MAX_PATH_LEN) == 0){
        // Handle mkdir
      }else if(strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0){
        // Handle create file
      }
      break;
    case PUT:
      if(strncmp(msg->path, "/files/content", HTTP_MAX_PATH_LEN) == 0){
        // Handle write file
      } 
      break;
    case PATCH:
      if(strncmp(msg->path, "/files/permissions", HTTP_MAX_PATH_LEN) == 0){
        // Handle perm change
      }
      break;
    case DELETE:
      if(strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0){
        // Handle rm
      }
      break;
    case UNKNOWN:
    default:
      break;
  }
  return req; // Shouldn't reach
}
