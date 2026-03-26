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
      if (strncmp(msg->path, "/groups", HTTP_MAX_PATH_LEN) == 0) {
        list_user_groups(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
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
        printf("HOLY WE POST LOGIN\n");
        char buf[HTTP_MAX_BODY_LEN];
        tls_read(ssl, buf, sizeof(buf));
        printf("%s\n", buf);
        res->status_code = 200;
        strncpy(res->reason, "Authorized", HTTP_MAX_QUERY_LEN);
        return res;
        // Handle login
      } else if (strncmp(msg->path, "/auth/register", HTTP_MAX_PATH_LEN) == 0) {
        // Handle registration
      } else if (strncmp(msg->path, "/auth/logout", HTTP_MAX_PATH_LEN) == 0) {
        // Handle logout
      } else if (strncmp(msg->path, "/files/move", HTTP_MAX_PATH_LEN) == 0) {
        // Handle mv
      } else if (strncmp(msg->path, "/directories", HTTP_MAX_PATH_LEN) == 0) {
        // Handle mkdir
      } else if (strncmp(msg->path, "/groups/members", HTTP_MAX_PATH_LEN) ==
                 0) {
        add_group_member(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/groups", HTTP_MAX_PATH_LEN) == 0) {
        create_group(msg, ssl, res, ctx);
        return res;
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
      if (strncmp(msg->path, "/groups/members", HTTP_MAX_PATH_LEN) == 0) {
        remove_group_member(msg, ssl, res, ctx);
        return res;
      } else if (strncmp(msg->path, "/files", HTTP_MAX_PATH_LEN) == 0) {
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
