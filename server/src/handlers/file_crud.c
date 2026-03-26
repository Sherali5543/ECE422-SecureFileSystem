#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "db.h"
#include "handlers.h"
#include "http.h"
#include "server_context.h"
#include "tls.h"

#define STORAGE_PATH_MAX 2048
#define CREATE_FILE_RESPONSE_MAX 1536

typedef struct {
  char* body;
  cJSON* json;
  const char* filepath;
} create_file_request_t;

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

static int ensure_storage_parent_dirs(const char* fullpath) {
  char tmp[STORAGE_PATH_MAX];
  char* slash = NULL;

  if (!fullpath || strlen(fullpath) >= sizeof(tmp)) {
    return -1;
  }

  strncpy(tmp, fullpath, sizeof(tmp) - 1);
  tmp[sizeof(tmp) - 1] = '\0';

  for (slash = tmp + 1; (slash = strchr(slash, '/')) != NULL; slash++) {
    *slash = '\0';
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
      perror("mkdir");
      return -1;
    }
    *slash = '/';
  }

  return 0;
}

static int create_empty_file_ctx(server_context_t* ctx, const char* filepath) {
  char fullpath[STORAGE_PATH_MAX];
  int fd = -1;

  if (build_storage_path(ctx, filepath, fullpath, sizeof(fullpath)) != 0) {
    return -1;
  }

  if (ensure_storage_parent_dirs(fullpath) != 0) {
    return -1;
  }

  fd = open(fullpath, O_CREAT | O_EXCL | O_WRONLY, 0644);
  if (fd < 0) {
    perror("open");
    return -1;
  }

  close(fd);
  return 0;
}

static void delete_backing_file(server_context_t* ctx, const char* filepath) {
  char fullpath[STORAGE_PATH_MAX];

  if (build_storage_path(ctx, filepath, fullpath, sizeof(fullpath)) != 0) {
    return;
  }

  if (unlink(fullpath) != 0 && errno != ENOENT) {
    perror("unlink");
  }
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

static int split_parent_child(const char* fullpath, char* parent,
                              size_t parent_sz, char* name, size_t name_sz) {
  const char* slash = NULL;
  size_t parent_len = 0;
  size_t name_len = 0;

  if (!fullpath || fullpath[0] != '/') {
    return -1;
  }

  slash = strrchr(fullpath, '/');
  if (!slash || *(slash + 1) == '\0') {
    return -1;
  }

  name_len = strlen(slash + 1);
  if (name_len == 0 || name_len >= name_sz) {
    return -1;
  }

  strncpy(name, slash + 1, name_sz - 1);
  name[name_sz - 1] = '\0';

  if (slash == fullpath) {
    if (parent_sz < 2) {
      return -1;
    }
    strcpy(parent, "/");
    return 0;
  }

  parent_len = (size_t)(slash - fullpath);
  if (parent_len >= parent_sz) {
    return -1;
  }

  memcpy(parent, fullpath, parent_len);
  parent[parent_len] = '\0';
  return 0;
}

static int is_valid_logical_path(const char* path) {
  const char* segment = NULL;

  if (!path || path[0] != '/' || strcmp(path, "/") == 0) {
    return 0;
  }

  for (segment = path + 1; *segment != '\0';) {
    const char* next_slash = strchr(segment, '/');
    size_t len = next_slash ? (size_t)(next_slash - segment) : strlen(segment);

    if (len == 0) {
      return 0;
    }
    if ((len == 1 && segment[0] == '.') ||
        (len == 2 && segment[0] == '.' && segment[1] == '.')) {
      return 0;
    }

    if (!next_slash) {
      break;
    }
    segment = next_slash + 1;
  }

  return path[strlen(path) - 1] != '/';
}

static int can_create_in_directory(server_context_t* ctx, int user_id,
                                   const db_file_metadata_t* parent_meta) {
  int is_member = 0;

  if (!ctx || !parent_meta) {
    return 0;
  }
  if (strcmp(parent_meta->object_type, "directory") != 0) {
    return 0;
  }
  if (parent_meta->owner_id == user_id && (parent_meta->mode_bits & 0200)) {
    return 1;
  }

  if (parent_meta->has_group_id &&
      db_is_user_in_group(ctx, user_id, parent_meta->group_id, &is_member) ==
          0 &&
      is_member && (parent_meta->mode_bits & 0020)) {
    return 1;
  }

  return (parent_meta->mode_bits & 0002) != 0;
}

static void cleanup_create_file_request(create_file_request_t* req) {
  if (!req) {
    return;
  }

  if (req->json) {
    cJSON_Delete(req->json);
  }
  free(req->body);
}

static int parse_create_file_request(http_message_t* msg, SSL* ssl,
                                     http_message_t* response,
                                     create_file_request_t* out_req,
                                     size_t* out_body_bytes_read) {
  cJSON* filepath_json = NULL;

  if (!msg || !ssl || !response || !out_req || !out_body_bytes_read) {
    return -1;
  }

  memset(out_req, 0, sizeof(*out_req));
  *out_body_bytes_read = 0;

  if (msg->content_type != JSON) {
    drain_body(ssl, msg->content_length);
    send_json_error(ssl, response, 415, "Unsupported Media Type",
                    "{\"error\":\"expected application/json\"}");
    return -1;
  }

  if (msg->content_length == 0 || msg->content_length > HTTP_MAX_BODY_LEN) {
    drain_body(ssl, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid content length\"}");
    return -1;
  }

  out_req->body = calloc(msg->content_length + 1, 1);
  if (!out_req->body) {
    drain_body(ssl, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"allocation failure\"}");
    return -1;
  }

  if (read_exact_body(ssl, out_req->body, msg->content_length) != 0) {
    send_bad_request(response, ssl);
    return -1;
  }
  *out_body_bytes_read = msg->content_length;

  out_req->json = cJSON_Parse(out_req->body);
  if (!out_req->json) {
    send_bad_request(response, ssl);
    return -1;
  }

  filepath_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "filepath");
  if (!cJSON_IsString(filepath_json) || filepath_json->valuestring == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  out_req->filepath = filepath_json->valuestring;
  if (strlen(out_req->filepath) >= DB_FILE_PATH_MAX ||
      !is_valid_logical_path(out_req->filepath)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid filepath\"}");
    return -1;
  }

  return 0;
}

static int populate_new_file_metadata(const char* filepath, const char* file_name,
                                      const server_session_t* session,
                                      const db_file_metadata_t* parent_meta,
                                      db_file_metadata_t* out_meta) {
  size_t filepath_len = 0;
  size_t file_name_len = 0;
  long long now = 0;

  if (!filepath || !file_name || !session || !parent_meta || !out_meta) {
    return -1;
  }

  filepath_len = strlen(filepath);
  file_name_len = strlen(file_name);
  now = (long long)time(NULL);

  memset(out_meta, 0, sizeof(*out_meta));
  memcpy(out_meta->path, filepath, filepath_len);
  out_meta->path_len = filepath_len;
  memcpy(out_meta->name, file_name, file_name_len);
  out_meta->name_len = file_name_len;
  out_meta->owner_id = session->user_id;
  out_meta->group_id = parent_meta->group_id;
  out_meta->has_group_id = parent_meta->has_group_id;
  out_meta->mode_bits = 0640;
  strncpy(out_meta->object_type, "file", sizeof(out_meta->object_type) - 1);
  out_meta->created_at = now;
  out_meta->updated_at = now;

  return 0;
}

static int create_file_metadata_and_backing_file(server_context_t* ctx,
                                                 const db_file_metadata_t* meta,
                                                 int* out_metadata_id) {
  if (db_begin_transaction(ctx) != 0) {
    return -1;
  }

  if (db_create_file_metadata(ctx, meta, out_metadata_id) != 0) {
    db_rollback(ctx);
    return -1;
  }

  if (create_empty_file_ctx(ctx, (const char*)meta->path) != 0) {
    db_rollback(ctx);
    return -1;
  }

  if (db_commit(ctx) != 0) {
    delete_backing_file(ctx, (const char*)meta->path);
    db_rollback(ctx);
    return -1;
  }

  return 0;
}

void create_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx) {
  create_file_request_t req = {0};
  char parent_path[DB_FILE_PATH_MAX];
  char file_name[DB_FILE_NAME_MAX];
  server_session_t session;
  db_file_metadata_t parent_meta;
  db_file_metadata_t existing_meta;
  db_file_metadata_t new_meta;
  size_t body_bytes_read = 0;
  int metadata_id = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->auth_token[0] == '\0') {
    drain_body(ssl, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }

  if (parse_create_file_request(msg, ssl, response, &req,
                                &body_bytes_read) != 0) {
    goto cleanup;
  }

  if (split_parent_child(req.filepath, parent_path, sizeof(parent_path),
                         file_name, sizeof(file_name)) != 0) {
    send_bad_request(response, ssl);
    goto cleanup;
  }

  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, parent_path, strlen(parent_path),
                                     &parent_meta);
  if (rc != 1) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"parent directory not found\"}");
    goto cleanup;
  }

  if (!can_create_in_directory(ctx, session.user_id, &parent_meta)) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, req.filepath, strlen(req.filepath),
                                     &existing_meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to check existing file\"}");
    goto cleanup;
  }
  if (rc == 1) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"file already exists\"}");
    goto cleanup;
  }

  if (populate_new_file_metadata(req.filepath, file_name, &session,
                                 &parent_meta, &new_meta) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build file metadata\"}");
    goto cleanup;
  }

  if (create_file_metadata_and_backing_file(ctx, &new_meta, &metadata_id) !=
      0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create file\"}");
    goto cleanup;
  }

  {
    char resp[CREATE_FILE_RESPONSE_MAX];
    int n = snprintf(
        resp, sizeof(resp),
        "{\"message\":\"file created\",\"filepath\":\"%s\",\"file_id\":%d}",
        req.filepath, metadata_id);

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
    drain_body(ssl, msg->content_length - body_bytes_read);
  }
  cleanup_create_file_request(&req);
}
