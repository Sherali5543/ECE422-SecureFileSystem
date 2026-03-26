#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cjson/cJSON.h"
#include "db.h"
#include "handlers.h"
#include "http.h"
#include "server_context.h"
#include "tls.h"

typedef struct {
  char* body;
  cJSON* json;
  const char* group_name;
} group_request_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* group_name;
  const char* username;
  const char* wrapped_group_key;
} group_member_request_t;

static void send_bad_request(http_message_t* response, SSL* ssl) {
  response->status_code = 400;
  strncpy(response->reason, "Bad request", sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  strncpy(response->connection, "close", sizeof(response->connection) - 1);
  response->connection[sizeof(response->connection) - 1] = '\0';
  response->content_type = NONE;
  response->content_length = 0;
  send_response(ssl, response);
}

static void set_json_response(http_message_t* response, int status,
                              const char* reason, size_t content_length) {
  response->status_code = status;
  strncpy(response->reason, reason, sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  response->content_type = JSON;
  response->content_length = content_length;
  strncpy(response->connection, "close", sizeof(response->connection) - 1);
  response->connection[sizeof(response->connection) - 1] = '\0';
}

static int write_json_body(SSL* ssl, const char* json) {
  size_t len = strlen(json);
  return (tls_write(ssl, (void*)json, len) == (ssize_t)len) ? 0 : -1;
}

static void send_json_error(SSL* ssl, http_message_t* response, int status,
                            const char* reason, const char* json_body) {
  set_json_response(response, status, reason, strlen(json_body));
  send_response(ssl, response);
  write_json_body(ssl, json_body);
}

static int read_exact_body(http_message_t* msg, SSL* ssl, char* buf,
                           size_t len) {
  if (read_message_body(ssl, msg, buf, len) != (ssize_t)len) {
    return -1;
  }

  buf[len] = '\0';
  return 0;
}

static int get_user_from_token(server_context_t* ctx, const char* token,
                               server_session_t* out_session) {
  time_t now = 0;

  if (!ctx || !token || !out_session) {
    return -1;
  }

  now = time(NULL);
  for (size_t i = 0; i < SERVER_MAX_SESSIONS; i++) {
    server_session_t* session = &ctx->sessions[i];

    if (!session->in_use) {
      continue;
    }
    if (strncmp(session->token, token, SERVER_MAX_TOKEN_LEN) != 0) {
      continue;
    }
    if (session->expires_at < now) {
      return -1;
    }

    *out_session = *session;
    return 0;
  }

  return -1;
}

static int is_valid_group_name(const char* group_name) {
  size_t len = 0;

  if (group_name == NULL) {
    return 0;
  }

  len = strlen(group_name);
  return len > 0 && len < DB_GROUP_NAME_MAX;
}

static void cleanup_group_request(group_request_t* req) {
  if (req == NULL) {
    return;
  }

  if (req->json != NULL) {
    cJSON_Delete(req->json);
  }
  free(req->body);
}

static void cleanup_group_member_request(group_member_request_t* req) {
  if (req == NULL) {
    return;
  }

  if (req->json != NULL) {
    cJSON_Delete(req->json);
  }
  free(req->body);
}

static int parse_group_request(http_message_t* msg, SSL* ssl,
                               http_message_t* response,
                               group_request_t* out_req,
                               size_t* out_body_bytes_read) {
  cJSON* group_name_json = NULL;

  if (!msg || !ssl || !response || !out_req || !out_body_bytes_read) {
    return -1;
  }

  memset(out_req, 0, sizeof(*out_req));
  *out_body_bytes_read = 0;

  if (msg->content_type != JSON) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 415, "Unsupported Media Type",
                    "{\"error\":\"expected application/json\"}");
    return -1;
  }
  if (msg->content_length == 0 || msg->content_length > HTTP_MAX_BODY_LEN) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid content length\"}");
    return -1;
  }

  out_req->body = calloc(msg->content_length + 1, 1);
  if (out_req->body == NULL) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"allocation failure\"}");
    return -1;
  }

  if (read_exact_body(msg, ssl, out_req->body, msg->content_length) != 0) {
    send_bad_request(response, ssl);
    return -1;
  }
  *out_body_bytes_read = msg->content_length;

  out_req->json = cJSON_Parse(out_req->body);
  if (out_req->json == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  group_name_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "group_name");
  if (!cJSON_IsString(group_name_json) || group_name_json->valuestring == NULL ||
      !is_valid_group_name(group_name_json->valuestring)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid group_name\"}");
    return -1;
  }

  out_req->group_name = group_name_json->valuestring;
  return 0;
}

static int parse_group_member_request(http_message_t* msg, SSL* ssl,
                                      http_message_t* response,
                                      group_member_request_t* out_req,
                                      size_t* out_body_bytes_read,
                                      int require_wrapped_group_key) {
  cJSON* group_name_json = NULL;
  cJSON* username_json = NULL;
  cJSON* wrapped_group_key_json = NULL;

  if (!msg || !ssl || !response || !out_req || !out_body_bytes_read) {
    return -1;
  }

  memset(out_req, 0, sizeof(*out_req));
  *out_body_bytes_read = 0;

  if (msg->content_type != JSON) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 415, "Unsupported Media Type",
                    "{\"error\":\"expected application/json\"}");
    return -1;
  }
  if (msg->content_length == 0 || msg->content_length > HTTP_MAX_BODY_LEN) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid content length\"}");
    return -1;
  }

  out_req->body = calloc(msg->content_length + 1, 1);
  if (out_req->body == NULL) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"allocation failure\"}");
    return -1;
  }

  if (read_exact_body(msg, ssl, out_req->body, msg->content_length) != 0) {
    send_bad_request(response, ssl);
    return -1;
  }
  *out_body_bytes_read = msg->content_length;

  out_req->json = cJSON_Parse(out_req->body);
  if (out_req->json == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  group_name_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "group_name");
  username_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "username");
  if (!cJSON_IsString(group_name_json) || group_name_json->valuestring == NULL ||
      !is_valid_group_name(group_name_json->valuestring) ||
      !cJSON_IsString(username_json) || username_json->valuestring == NULL ||
      username_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid group_name or username\"}");
    return -1;
  }

  out_req->group_name = group_name_json->valuestring;
  out_req->username = username_json->valuestring;

  if (require_wrapped_group_key) {
    wrapped_group_key_json =
        cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_group_key");
    if (!cJSON_IsString(wrapped_group_key_json) ||
        wrapped_group_key_json->valuestring == NULL ||
        wrapped_group_key_json->valuestring[0] == '\0') {
      send_json_error(ssl, response, 400, "Bad Request",
                      "{\"error\":\"invalid wrapped_group_key\"}");
      return -1;
    }

    out_req->wrapped_group_key = wrapped_group_key_json->valuestring;
  }

  return 0;
}

static int parse_username_query(const http_message_t* msg, char* out_username,
                                size_t out_size) {
  static const char prefix[] = "username=";
  const char* value = NULL;
  size_t len = 0;

  if (!msg || !out_username || out_size == 0) {
    return -1;
  }
  if (msg->query[0] == '\0') {
    return 1;
  }
  if (strncmp(msg->query, prefix, sizeof(prefix) - 1) != 0) {
    return -1;
  }

  value = msg->query + sizeof(prefix) - 1;
  if (*value == '\0' || strchr(value, '&') != NULL) {
    return -1;
  }

  len = strlen(value);
  if (len >= out_size) {
    return -1;
  }

  memcpy(out_username, value, len);
  out_username[len] = '\0';
  return 0;
}

void create_group(http_message_t* msg, SSL* ssl, http_message_t* response,
                  server_context_t* ctx) {
  group_request_t req = {0};
  server_session_t session;
  db_group_t existing_group;
  size_t body_bytes_read = 0;
  int group_id = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }
  if (parse_group_request(msg, ssl, response, &req, &body_bytes_read) != 0) {
    goto cleanup;
  }

  rc = db_find_group_by_name(ctx, req.group_name, &existing_group);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to check existing group\"}");
    goto cleanup;
  }
  if (rc == 1) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"group already exists\"}");
    goto cleanup;
  }
  if (db_create_group(ctx, req.group_name, &group_id) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create group\"}");
    goto cleanup;
  }

  {
    char resp[512];
    int n = snprintf(resp, sizeof(resp),
                     "{\"message\":\"group created\",\"group_name\":\"%s\","
                     "\"group_id\":%d}",
                     req.group_name, group_id);
    if (n < 0 || (size_t)n >= sizeof(resp)) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"response build failure\"}");
      goto cleanup;
    }

    set_json_response(response, 201, "Created", (size_t)n);
    send_response(ssl, response);
    write_json_body(ssl, resp);
  }

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_group_request(&req);
}

void add_group_member(http_message_t* msg, SSL* ssl, http_message_t* response,
                      server_context_t* ctx) {
  group_member_request_t req = {0};
  server_session_t session;
  db_group_t group;
  db_user_t user;
  int is_member = 0;
  size_t body_bytes_read = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }
  if (parse_group_member_request(msg, ssl, response, &req, &body_bytes_read,
                                 1) != 0) {
    goto cleanup;
  }

  rc = db_find_group_by_name(ctx, req.group_name, &group);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load group\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"group not found\"}");
    goto cleanup;
  }

  rc = db_find_user_by_username(ctx, req.username, &user);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load user\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"user not found\"}");
    goto cleanup;
  }

  if (db_is_user_in_group(ctx, user.id, group.id, &is_member) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to check membership\"}");
    goto cleanup;
  }
  if (is_member) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"user already in group\"}");
    goto cleanup;
  }

  if (db_add_user_to_group(ctx, user.id, group.id, req.wrapped_group_key,
                           strlen(req.wrapped_group_key)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to add user to group\"}");
    goto cleanup;
  }

  send_json_error(ssl, response, 200, "OK",
                  "{\"message\":\"user added to group\"}");

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_group_member_request(&req);
}

void remove_group_member(http_message_t* msg, SSL* ssl,
                         http_message_t* response, server_context_t* ctx) {
  group_member_request_t req = {0};
  server_session_t session;
  db_group_t group;
  db_user_t user;
  size_t body_bytes_read = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }
  if (parse_group_member_request(msg, ssl, response, &req, &body_bytes_read,
                                 0) != 0) {
    goto cleanup;
  }

  rc = db_find_group_by_name(ctx, req.group_name, &group);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load group\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"group not found\"}");
    goto cleanup;
  }

  rc = db_find_user_by_username(ctx, req.username, &user);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load user\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"user not found\"}");
    goto cleanup;
  }

  rc = db_remove_user_from_group(ctx, user.id, group.id);
  if (rc < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to remove user from group\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"user is not in group\"}");
    goto cleanup;
  }

  send_json_error(ssl, response, 200, "OK",
                  "{\"message\":\"user removed from group\"}");

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_group_member_request(&req);
}

void list_user_groups(http_message_t* msg, SSL* ssl, http_message_t* response,
                      server_context_t* ctx) {
  server_session_t session;
  db_user_t user;
  db_group_membership_t* memberships = NULL;
  cJSON* root = NULL;
  cJSON* groups_json = NULL;
  char username[DB_USERNAME_MAX];
  char* json = NULL;
  size_t group_count = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = parse_username_query(msg, username, sizeof(username));
  if (rc < 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid username query\"}");
    return;
  }
  if (rc > 0) {
    strncpy(username, session.username, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';
  }

  rc = db_find_user_by_username(ctx, username, &user);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load user\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"user not found\"}");
    return;
  }

  if (db_get_user_groups(ctx, user.id, NULL, 0, &group_count) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load groups\"}");
    return;
  }

  if (group_count > 0) {
    memberships = calloc(group_count, sizeof(*memberships));
    if (memberships == NULL) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"allocation failure\"}");
      return;
    }

    if (db_get_user_groups(ctx, user.id, memberships, group_count,
                           &group_count) != 0) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"failed to load groups\"}");
      goto cleanup;
    }
  }

  root = cJSON_CreateObject();
  groups_json = cJSON_AddArrayToObject(root, "groups");
  cJSON_AddStringToObject(root, "username", user.username);

  for (size_t i = 0; i < group_count; i++) {
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "group_id", memberships[i].group.id);
    cJSON_AddStringToObject(item, "group_name", memberships[i].group.name);
    cJSON_AddItemToArray(groups_json, item);
  }

  json = cJSON_PrintUnformatted(root);
  if (json == NULL) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"response build failure\"}");
    goto cleanup;
  }

  set_json_response(response, 200, "OK", strlen(json));
  send_response(ssl, response);
  write_json_body(ssl, json);

cleanup:
  free(json);
  if (root != NULL) {
    cJSON_Delete(root);
  }
  free(memberships);
}
