#include "routing.h"

#include <stdio.h>

#include "http.h"
#include "string.h"
#include "tls.h"
#include "handlers.h"

http_message_t* handle_request(http_message_t* msg, SSL* ssl, server_context_t *ctx) {
  http_message_t* res = init_response();

  switch (msg->method) {
    case GET:
      if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
        // get_files(msg, ssl, res); // Ls/cd
        return res;
      } else if (strncmp(msg->path, "/files/contents", HTTP_MAX_PATH_LEN) ==
                 0) {
        read_file(msg, ssl, res, ctx);
        return res;
      }
      break;
    case POST:
      if (strncmp(msg->path, "/auth/login", HTTP_MAX_PATH_LEN) == 0) {
        login_user(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/auth/register", HTTP_MAX_PATH_LEN) == 0) {
        register_user(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/auth/logout", HTTP_MAX_PATH_LEN) == 0) {
        logout_user(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/files/move", HTTP_MAX_PATH_LEN) == 0) {
        // Handle mv
      } else if (strncmp(msg->path, "/directories", HTTP_MAX_PATH_LEN) == 0) {
        // Handle mkdir
      } else if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
        // Handle create file
        create_file(msg, ssl, res, ctx);
        return res;
      }
      break;
    case PUT:
      if (strncmp(msg->path, "/files/content", HTTP_MAX_PATH_LEN) == 0) {
        write_file(msg, ssl, res, ctx);
        return res;
      }
      break;
    case PATCH:
      if (strncmp(msg->path, "/files/permissions", HTTP_MAX_PATH_LEN) == 0) {
        // Handle perm change
      }
      break;
    case DELETE:
      if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
        delete_file(msg, ssl, res, ctx);
        return res;
      }
      break;
    case UNKNOWN:
    default:
      break;
  }
  printf("I shouldn't be here\n");
  return res;  // Shouldn't reach
}
