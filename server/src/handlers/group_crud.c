#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
  const char* wrapped_group_key_hex;
  const char* groups_root_path;
  const char* groups_root_name;
  const char* group_dir_path;
  const char* group_dir_name;
} group_request_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* group_name;
  const char* username;
  const char* wrapped_group_key_hex;
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

static int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

static int decode_hex_string(const char* hex, unsigned char* out,
                             size_t out_cap, size_t* out_len) {
  size_t hex_len = 0;

  if (!hex || !out || !out_len) {
    return -1;
  }

  hex_len = strlen(hex);
  if ((hex_len % 2) != 0 || (hex_len / 2) > out_cap) {
    return -1;
  }

  for (size_t i = 0; i < hex_len; i += 2) {
    int hi = hex_value(hex[i]);
    int lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i / 2] = (unsigned char)((hi << 4) | lo);
  }

  *out_len = hex_len / 2;
  return 0;
}

static int encode_hex_string(const unsigned char* data, size_t data_len,
                             char* out, size_t out_cap) {
  static const char hex_chars[] = "0123456789abcdef";

  if (!out || out_cap == 0) {
    return -1;
  }
  if ((data_len > 0 && data == NULL) || (data_len * 2 + 1) > out_cap) {
    return -1;
  }

  for (size_t i = 0; i < data_len; i++) {
    out[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex_chars[data[i] & 0x0F];
  }
  out[data_len * 2] = '\0';
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

static int is_valid_encrypted_path_string(const char* path) {
  size_t len = 0;

  if (path == NULL || path[0] != '/') {
    return 0;
  }

  len = strlen(path);
  if (len <= 1 || len >= DB_FILE_PATH_MAX || path[len - 1] == '/') {
    return 0;
  }

  return 1;
}

static int is_valid_encrypted_name_string(const char* name) {
  size_t len = 0;

  if (name == NULL) {
    return 0;
  }

  len = strlen(name);
  return len > 0 && len < DB_FILE_NAME_MAX && strchr(name, '/') == NULL;
}

static int build_storage_path(server_context_t* ctx, const char* filepath,
                              char* out, size_t out_sz) {
  int written = 0;

  if (!ctx || !ctx->storage_root || !filepath || !out || out_sz == 0) {
    return -1;
  }

  written = snprintf(out, out_sz, "%s%s", ctx->storage_root, filepath);
  if (written < 0 || (size_t)written >= out_sz) {
    return -1;
  }

  return 0;
}

static int create_directory_ctx(server_context_t* ctx, const char* dirpath) {
  char fullpath[DB_FILE_PATH_MAX * 2];

  if (!ctx || !dirpath) {
    return -1;
  }
  if (build_storage_path(ctx, dirpath, fullpath, sizeof(fullpath)) != 0) {
    return -1;
  }
  if (mkdir(fullpath, 0755) != 0 && errno != EEXIST) {
    return -1;
  }
  return 0;
}

static int populate_directory_metadata(db_file_metadata_t* out_meta,
                                       const char* path, const char* name,
                                       int owner_id, int has_group_id,
                                       int group_id, int mode_bits) {
  size_t path_len = 0;
  size_t name_len = 0;
  long long now = (long long)time(NULL);

  if (!out_meta || !path || !name) {
    return -1;
  }

  path_len = strlen(path);
  name_len = strlen(name);
  if (path_len >= sizeof(out_meta->path) || name_len >= sizeof(out_meta->name)) {
    return -1;
  }

  memset(out_meta, 0, sizeof(*out_meta));
  memcpy(out_meta->path, path, path_len);
  out_meta->path_len = path_len;
  memcpy(out_meta->name, name, name_len);
  out_meta->name_len = name_len;
  out_meta->owner_id = owner_id;
  out_meta->has_group_id = has_group_id;
  out_meta->group_id = group_id;
  out_meta->mode_bits = mode_bits;
  strncpy(out_meta->object_type, "directory",
          sizeof(out_meta->object_type) - 1);
  out_meta->created_at = now;
  out_meta->updated_at = now;
  return 0;
}

static int ensure_shared_group_directories(server_context_t* ctx,
                                           const group_request_t* req,
                                           int owner_id, int group_id) {
  db_file_metadata_t existing = {0};
  db_file_metadata_t root_meta = {0};
  db_file_metadata_t group_meta = {0};
  int rc = 0;

  if (!ctx || !req) {
    return -1;
  }

  rc = db_find_file_metadata_by_path(ctx, req->groups_root_path,
                                     strlen(req->groups_root_path), &existing);
  if (rc == -1) {
    return -1;
  }
  if (rc == 0) {
    if (populate_directory_metadata(&root_meta, req->groups_root_path,
                                    req->groups_root_name, owner_id, 0, 0,
                                    0755) != 0 ||
        db_create_file_metadata(ctx, &root_meta, NULL) != 0 ||
        create_directory_ctx(ctx, req->groups_root_path) != 0) {
      return -1;
    }
  } else if (strncmp(existing.object_type, "directory",
                     sizeof(existing.object_type)) != 0) {
    return -1;
  }

  rc = db_find_file_metadata_by_path(ctx, req->group_dir_path,
                                     strlen(req->group_dir_path), &existing);
  if (rc == -1) {
    return -1;
  }
  if (rc == 1) {
    return strncmp(existing.object_type, "directory",
                   sizeof(existing.object_type)) == 0
               ? 0
               : -1;
  }

  if (populate_directory_metadata(&group_meta, req->group_dir_path,
                                  req->group_dir_name, owner_id, 1, group_id,
                                  0770) != 0 ||
      db_create_file_metadata(ctx, &group_meta, NULL) != 0 ||
      create_directory_ctx(ctx, req->group_dir_path) != 0) {
    return -1;
  }

  return 0;
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
  cJSON* wrapped_group_key_json = NULL;
  cJSON* groups_root_path_json = NULL;
  cJSON* groups_root_name_json = NULL;
  cJSON* group_dir_path_json = NULL;
  cJSON* group_dir_name_json = NULL;

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
  wrapped_group_key_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_group_key");
  groups_root_path_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "groups_root_path");
  groups_root_name_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "groups_root_name");
  group_dir_path_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "group_dir_path");
  group_dir_name_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "group_dir_name");
  if (!cJSON_IsString(group_name_json) || group_name_json->valuestring == NULL ||
      !is_valid_group_name(group_name_json->valuestring) ||
      !cJSON_IsString(wrapped_group_key_json) ||
      wrapped_group_key_json->valuestring == NULL ||
      wrapped_group_key_json->valuestring[0] == '\0' ||
      !cJSON_IsString(groups_root_path_json) ||
      !is_valid_encrypted_path_string(groups_root_path_json->valuestring) ||
      !cJSON_IsString(groups_root_name_json) ||
      !is_valid_encrypted_name_string(groups_root_name_json->valuestring) ||
      !cJSON_IsString(group_dir_path_json) ||
      !is_valid_encrypted_path_string(group_dir_path_json->valuestring) ||
      !cJSON_IsString(group_dir_name_json) ||
      !is_valid_encrypted_name_string(group_dir_name_json->valuestring)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid group create request\"}");
    return -1;
  }

  out_req->group_name = group_name_json->valuestring;
  out_req->wrapped_group_key_hex = wrapped_group_key_json->valuestring;
  out_req->groups_root_path = groups_root_path_json->valuestring;
  out_req->groups_root_name = groups_root_name_json->valuestring;
  out_req->group_dir_path = group_dir_path_json->valuestring;
  out_req->group_dir_name = group_dir_name_json->valuestring;
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

    out_req->wrapped_group_key_hex = wrapped_group_key_json->valuestring;
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

static int parse_group_name_query(const http_message_t* msg, char* out_group_name,
                                  size_t out_size) {
  static const char prefix[] = "group_name=";
  const char* value = NULL;
  size_t len = 0;

  if (!msg || !out_group_name || out_size == 0) {
    return -1;
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

  memcpy(out_group_name, value, len);
  out_group_name[len] = '\0';
  return is_valid_group_name(out_group_name) ? 0 : -1;
}

static int ensure_group_owner(SSL* ssl, http_message_t* response,
                              const server_session_t* session,
                              const db_group_t* group) {
  if (!session || !group) {
    return -1;
  }
  if (group->owner_id != session->user_id) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"only the group owner can manage members\"}");
    return -1;
  }

  return 0;
}

void create_group(http_message_t* msg, SSL* ssl, http_message_t* response,
                  server_context_t* ctx) {
  group_request_t req = {0};
  server_session_t session;
  db_group_t existing_group;
  unsigned char wrapped_group_key[DB_WRAPPED_KEY_MAX];
  size_t wrapped_group_key_len = 0;
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
  if (decode_hex_string(req.wrapped_group_key_hex, wrapped_group_key,
                        sizeof(wrapped_group_key),
                        &wrapped_group_key_len) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_group_key\"}");
    goto cleanup;
  }

  if (db_begin_transaction(ctx) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create group\"}");
    goto cleanup;
  }
  if (db_create_group(ctx, req.group_name, session.user_id, &group_id) != 0 ||
      db_add_user_to_group(ctx, session.user_id, group_id, wrapped_group_key,
                           wrapped_group_key_len) != 0 ||
      ensure_shared_group_directories(ctx, &req, session.user_id, group_id) != 0) {
    db_rollback(ctx);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create group\"}");
    goto cleanup;
  }
  if (db_commit(ctx) != 0) {
    db_rollback(ctx);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create group\"}");
    goto cleanup;
  }

  {
    char resp[512];
    int n = snprintf(resp, sizeof(resp),
                     "{\"message\":\"group created\",\"group_name\":\"%s\","
                     "\"group_id\":%d,\"owner_id\":%d}",
                     req.group_name, group_id, session.user_id);
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
  unsigned char wrapped_group_key[DB_WRAPPED_KEY_MAX];
  size_t wrapped_group_key_len = 0;
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
  if (ensure_group_owner(ssl, response, &session, &group) != 0) {
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
  if (decode_hex_string(req.wrapped_group_key_hex, wrapped_group_key,
                        sizeof(wrapped_group_key),
                        &wrapped_group_key_len) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_group_key\"}");
    goto cleanup;
  }

  if (db_add_user_to_group(ctx, user.id, group.id, wrapped_group_key,
                           wrapped_group_key_len) != 0) {
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
  if (ensure_group_owner(ssl, response, &session, &group) != 0) {
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
  if (user.id == group.owner_id) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"cannot remove the group owner\"}");
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
    cJSON_AddNumberToObject(item, "owner_id", memberships[i].group.owner_id);
    cJSON_AddBoolToObject(item, "is_owner",
                          memberships[i].group.owner_id == user.id);
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

void get_group_key(http_message_t* msg, SSL* ssl, http_message_t* response,
                   server_context_t* ctx) {
  server_session_t session;
  db_group_t group;
  db_group_membership_t membership;
  char group_name[DB_GROUP_NAME_MAX];
  char wrapped_group_key_hex[HTTP_MAX_HEADER_VALUE];
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
  if (parse_group_name_query(msg, group_name, sizeof(group_name)) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid group_name query\"}");
    return;
  }

  rc = db_find_group_by_name(ctx, group_name, &group);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load group\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"group not found\"}");
    return;
  }

  rc = db_find_user_group_membership(ctx, session.user_id, group.id,
                                     &membership);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load group membership\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"user is not a member of the group\"}");
    return;
  }
  if (encode_hex_string(membership.wrapped_group_key,
                        membership.wrapped_group_key_len, wrapped_group_key_hex,
                        sizeof(wrapped_group_key_hex)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to encode wrapped group key\"}");
    return;
  }

  {
    char resp[2048];
    int n = snprintf(resp, sizeof(resp),
                     "{\"group_id\":%d,\"group_name\":\"%s\",\"owner_id\":%d,"
                     "\"wrapped_group_key\":\"%s\"}",
                     group.id, group.name, group.owner_id,
                     wrapped_group_key_hex);
    if (n < 0 || (size_t)n >= sizeof(resp)) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"response build failure\"}");
      return;
    }

    set_json_response(response, 200, "OK", (size_t)n);
    send_response(ssl, response);
    write_json_body(ssl, resp);
  }
}
