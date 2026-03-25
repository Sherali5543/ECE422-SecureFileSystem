#include "routes.h"

#include <string.h>

#include "auth.h"
#include "permissions.h"
#include "storage.h"

static void set_json_response(http_message_t* response, int status_code,
                              const char* reason, const char* json_body) {
  response->status_code = status_code;
  strncpy(response->reason, reason, sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  strncpy(response->content_type, "application/json",
          sizeof(response->content_type) - 1);
  response->content_type[sizeof(response->content_type) - 1] = '\0';
  strncpy((char*)response->body, json_body, sizeof(response->body) - 1);
  response->body[sizeof(response->body) - 1] = '\0';
  response->body_len = strlen((char*)response->body);
  response->content_length = response->body_len;
}

int route_request(server_context_t* ctx, const http_message_t* request,
                  http_message_t* response) {
  if (request->method == POST && strcmp(request->path, "/auth/login") == 0) {
    return auth_handle_login(ctx, request, response);
  }
  if (request->method == POST && strcmp(request->path, "/auth/register") == 0) {
    return auth_handle_register(ctx, request, response);
  }

  if (auth_validate_token(ctx, request) != 0) {
    set_json_response(response, 401, "Unauthorized",
                      "{\"error\":\"missing or invalid auth token\"}");
    return 0;
  }

  if (request->method == GET && strcmp(request->path, "/fs/read") == 0) {
    if (permissions_check(ctx, request, "read") != 0) {
      set_json_response(response, 403, "Forbidden",
                        "{\"error\":\"read permission denied\"}");
      return 0;
    }
    return storage_read_file(ctx, request, response);
  }

  if (request->method == PUT && strcmp(request->path, "/fs/write") == 0) {
    if (permissions_check(ctx, request, "write") != 0) {
      set_json_response(response, 403, "Forbidden",
                        "{\"error\":\"write permission denied\"}");
      return 0;
    }
    return storage_write_file(ctx, request, response);
  }

  if (request->method == GET && strcmp(request->path, "/fs/list") == 0) {
    if (permissions_check(ctx, request, "list") != 0) {
      set_json_response(response, 403, "Forbidden",
                        "{\"error\":\"list permission denied\"}");
      return 0;
    }
    set_json_response(response, 501, "Not Implemented",
                      "{\"error\":\"list handler not implemented\"}");
    return 0;
  }

  if (request->method == POST && strcmp(request->path, "/fs/mkdir") == 0) {
    if (permissions_check(ctx, request, "mkdir") != 0) {
      set_json_response(response, 403, "Forbidden",
                        "{\"error\":\"mkdir permission denied\"}");
      return 0;
    }
    set_json_response(response, 501, "Not Implemented",
                      "{\"error\":\"mkdir handler not implemented\"}");
    return 0;
  }

  set_json_response(response, 404, "Not Found",
                    "{\"error\":\"unknown route\"}");
  return 0;
}
