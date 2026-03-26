#include <errno.h>
#include <limits.h>
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

static void send_400_response(http_message_t* response, SSL* ssl) {
  response->status_code = 400;
  strncpy(response->reason, "Bad request", HTTP_MAX_QUERY_LEN);
  strncpy(response->connection, "close", HTTP_MAX_HEADER_VALUE);
  response->content_type = NONE;
  response->content_length = 0;
  send_response(ssl, response);
}

static void set_json_response(http_message_t* response, int status,
                              const char* reason, const char* connection,
                              size_t content_length) {
  response->status_code = status;
  strncpy(response->reason, reason, sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';

  response->content_type = JSON;
  response->content_length = content_length;

  strncpy(response->connection, connection, sizeof(response->connection) - 1);
  response->connection[sizeof(response->connection) - 1] = '\0';
}

static int write_json_body(SSL* ssl, const char* json) {
  size_t len = strlen(json);
  return (tls_write(ssl, (void*)json, len) == (ssize_t)len) ? 0 : -1;
}

static int send_json_immediate(SSL* ssl, http_message_t* response, int status,
                               const char* reason, const char* json_body) {
  set_json_response(response, status, reason, "close", strlen(json_body));
  send_response(ssl, response);
  return write_json_body(ssl, json_body);
}

static int read_exact_body(SSL* ssl, char* buf, size_t len) {
  size_t total = 0;

  while (total < len) {
    ssize_t n = tls_read(ssl, buf + total, len - total);
    if (n <= 0) {
      return -1;
    }
    total += (size_t)n;
  }

  buf[len] = '\0';
  return 0;
}

static int get_user_from_token(server_context_t* ctx, const char* token,
                               server_session_t* out_session) {
  if (!ctx || !token || !out_session) return -1;

  time_t now = time(NULL);

  for (size_t i = 0; i < SERVER_MAX_SESSIONS; i++) {
    if (!ctx->sessions[i].in_use) continue;

    if (strncmp(ctx->sessions[i].token, token, SERVER_MAX_TOKEN_LEN) == 0) {
      if (ctx->sessions[i].expires_at < now) {
        return -1;
      }

      *out_session = ctx->sessions[i];
      return 0;
    }
  }

  return -1;
}

static int split_parent_child(const char* fullpath, char* parent,
                              size_t parent_sz, char* name, size_t name_sz) {
  const char* slash = NULL;
  size_t parent_len = 0;
  size_t name_len = 0;

  if (!fullpath || fullpath[0] != '/') return -1;

  slash = strrchr(fullpath, '/');
  if (!slash) return -1;
  if (*(slash + 1) == '\0') return -1;  // path ends with '/'

  name_len = strlen(slash + 1);
  if (name_len == 0 || name_len >= name_sz) return -1;

  strncpy(name, slash + 1, name_sz - 1);
  name[name_sz - 1] = '\0';

  if (slash == fullpath) {
    // parent is "/"
    if (parent_sz < 2) return -1;
    strcpy(parent, "/");
    return 0;
  }

  parent_len = (size_t)(slash - fullpath);
  if (parent_len >= parent_sz) return -1;

  memcpy(parent, fullpath, parent_len);
  parent[parent_len] = '\0';
  return 0;
}

/*
 * Simplified permission rule:
 * caller can create inside a directory if:
 *   - caller owns directory and owner write bit set, OR
 *   - caller is in directory group and group write bit set, OR
 *   - other write bit set
 *
 * Assumes POSIX-ish bits:
 *   owner write = 0200
 *   group write = 0020
 *   other write = 0002
 */
static int can_create_in_directory(server_context_t* ctx, int user_id,
                                   const db_file_metadata_t* parent_meta) {
  int is_member = 0;

  if (!ctx || !parent_meta) return 0;
  if (strcmp(parent_meta->object_type, "dir") != 0) return 0;

  if (parent_meta->owner_id == user_id && (parent_meta->mode_bits & 0200)) {
    return 1;
  }

  if (parent_meta->has_group_id) {
    if (db_is_user_in_group(ctx, user_id, parent_meta->group_id, &is_member) ==
            0 &&
        is_member && (parent_meta->mode_bits & 0020)) {
      return 1;
    }
  }

  if (parent_meta->mode_bits & 0002) {
    return 1;
  }

  return 0;
}

void create_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx) {
  char* body = NULL;
  cJSON* root = NULL;
  cJSON* filepath_json = NULL;

  char parent_path[DB_FILE_PATH_MAX];
  char file_name[DB_FILE_NAME_MAX];

  server_session_t session;
  db_file_metadata_t parent_meta;
  db_file_metadata_t existing_meta;
  db_file_metadata_t new_meta;

  int rc = -1;
  int metadata_id = 0;
  size_t body_bytes_read = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->content_type != JSON) {
    drain_body(ssl, msg->content_length);
    send_json_immediate(ssl, response, 415, "Unsupported Media Type",
                        "{\"error\":\"expected application/json\"}");
    return;
  }

  if (msg->auth_token[0] == '\0') {
    drain_body(ssl, msg->content_length);
    send_json_immediate(ssl, response, 401, "Unauthorized",
                        "{\"error\":\"missing bearer token\"}");
    return;
  }

  if (msg->content_length == 0 || msg->content_length > HTTP_MAX_BODY_LEN) {
    drain_body(ssl, msg->content_length);
    send_json_immediate(ssl, response, 400, "Bad Request",
                        "{\"error\":\"invalid content length\"}");
    return;
  }

  body = calloc(msg->content_length + 1, 1);
  if (!body) {
    drain_body(ssl, msg->content_length);
    send_json_immediate(ssl, response, 500, "Internal Server Error",
                        "{\"error\":\"allocation failure\"}");
    return;
  }

  if (read_exact_body(ssl, body, msg->content_length) != 0) {
    send_400_response(response, ssl);
    goto cleanup;
  }
  body_bytes_read = msg->content_length;

  root = cJSON_Parse(body);
  if (!root) {
    send_400_response(response, ssl);
    goto cleanup;
  }

  filepath_json = cJSON_GetObjectItemCaseSensitive(root, "filepath");
  if (!cJSON_IsString(filepath_json) || filepath_json->valuestring == NULL) {
    send_400_response(response, ssl);
    goto cleanup;
  }

  if (strlen(filepath_json->valuestring) >= DB_FILE_PATH_MAX) {
    send_400_response(response, ssl);
    goto cleanup;
  }

  if (split_parent_child(filepath_json->valuestring, parent_path,
                         sizeof(parent_path), file_name,
                         sizeof(file_name)) != 0) {
    send_400_response(response, ssl);
    goto cleanup;
  }

  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_immediate(ssl, response, 401, "Unauthorized",
                        "{\"error\":\"invalid or expired token\"}");
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, parent_path, strlen(parent_path),
                                     &parent_meta);
  if (rc != 0) {
    send_json_immediate(ssl, response, 404, "Not Found",
                        "{\"error\":\"parent directory not found\"}");
    goto cleanup;
  }

  if (!can_create_in_directory(ctx, session.user_id, &parent_meta)) {
    send_json_immediate(ssl, response, 403, "Forbidden",
                        "{\"error\":\"insufficient permissions\"}");
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, filepath_json->valuestring,
                                     strlen(filepath_json->valuestring),
                                     &existing_meta);
  if (rc == 0) {
    send_json_immediate(ssl, response, 409, "Conflict",
                        "{\"error\":\"file already exists\"}");
    goto cleanup;
  }

  memset(&new_meta, 0, sizeof(new_meta));
  memcpy(new_meta.path, filepath_json->valuestring,
         strlen(filepath_json->valuestring));
  new_meta.path_len = strlen(filepath_json->valuestring);

  memcpy(new_meta.name, file_name, strlen(file_name));
  new_meta.name_len = strlen(file_name);

  new_meta.owner_id = session.user_id;
  new_meta.group_id = parent_meta.group_id;
  new_meta.has_group_id = parent_meta.has_group_id;
  new_meta.mode_bits = 0640;
  strncpy(new_meta.object_type, "file", sizeof(new_meta.object_type) - 1);
  new_meta.created_at = (long long)time(NULL);
  new_meta.updated_at = (long long)time(NULL);

  if (db_begin_transaction(ctx) != 0) {
    send_json_immediate(ssl, response, 500, "Internal Server Error",
                        "{\"error\":\"failed to begin transaction\"}");
    goto cleanup;
  }

  if (db_create_file_metadata(ctx, &new_meta, &metadata_id) != 0) {
    db_rollback(ctx);
    send_json_immediate(ssl, response, 500, "Internal Server Error",
                        "{\"error\":\"failed to create file metadata\"}");
    goto cleanup;
  }

  if (db_commit(ctx) != 0) {
    db_rollback(ctx);
    send_json_immediate(ssl, response, 500, "Internal Server Error",
                        "{\"error\":\"failed to commit transaction\"}");
    goto cleanup;
  }

  {
    char resp[1536];
    int n = snprintf(
        resp, sizeof(resp),
        "{\"message\":\"file created\",\"filepath\":\"%s\",\"file_id\":%d}",
        filepath_json->valuestring, metadata_id);

    if (n < 0 || (size_t)n >= sizeof(resp)) {
      send_json_immediate(ssl, response, 500, "Internal Server Error",
                          "{\"error\":\"response build failure\"}");
      goto cleanup;
    }

    set_json_response(response, 201, "Created", "close", (size_t)n);
    send_response(ssl, response);
    write_json_body(ssl, resp);
  }

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_body(ssl, msg->content_length - body_bytes_read);
  }
  if (root) cJSON_Delete(root);
  free(body);
}
