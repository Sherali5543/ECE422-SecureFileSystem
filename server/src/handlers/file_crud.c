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
  const char* group_name;
  const char* wrapped_fek_owner_hex;
  const char* wrapped_fek_group_hex;
  const char* wrapped_fek_other_hex;
} create_file_request_t;

typedef struct {
  char filepath[DB_FILE_PATH_MAX];
} filepath_query_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* dirpath;
} create_directory_request_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* source_filepath;
  const char* destination_filepath;
} move_file_request_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* filepath;
  int mode_bits;
  const char* wrapped_fek_owner_hex;
  const char* wrapped_fek_group_hex;
  const char* wrapped_fek_other_hex;
} permissions_request_t;

typedef struct {
  db_file_metadata_t* items;
  size_t count;
  size_t capacity;
} metadata_vec_t;

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

static int create_directory_ctx(server_context_t* ctx, const char* dirpath) {
  char fullpath[STORAGE_PATH_MAX];

  if (build_storage_path(ctx, dirpath, fullpath, sizeof(fullpath)) != 0) {
    return -1;
  }
  if (ensure_storage_parent_dirs(fullpath) != 0) {
    return -1;
  }
  if (mkdir(fullpath, 0755) != 0) {
    perror("mkdir");
    return -1;
  }

  return 0;
}

static int rename_storage_path(server_context_t* ctx, const char* old_path,
                               const char* new_path) {
  char old_fullpath[STORAGE_PATH_MAX];
  char new_fullpath[STORAGE_PATH_MAX];

  if (build_storage_path(ctx, old_path, old_fullpath, sizeof(old_fullpath)) !=
          0 ||
      build_storage_path(ctx, new_path, new_fullpath, sizeof(new_fullpath)) !=
          0) {
    return -1;
  }
  if (ensure_storage_parent_dirs(new_fullpath) != 0) {
    return -1;
  }
  if (rename(old_fullpath, new_fullpath) != 0) {
    perror("rename");
    return -1;
  }

  return 0;
}

static int blob_to_cstring(const unsigned char* blob, size_t blob_len,
                           char* out, size_t out_sz) {
  if (!out || out_sz == 0 || blob_len >= out_sz) {
    return -1;
  }

  if (blob_len > 0 && blob == NULL) {
    return -1;
  }

  if (blob_len > 0) {
    memcpy(out, blob, blob_len);
  }
  out[blob_len] = '\0';
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

static int set_wrapped_fek_from_hex(const char* hex, int required,
                                    unsigned char* out_buf,
                                    size_t out_buf_cap, size_t* out_len,
                                    int* out_has_value) {
  if (!out_buf || !out_len || !out_has_value) {
    return -1;
  }

  *out_len = 0;
  *out_has_value = 0;
  if (hex == NULL) {
    return required ? -1 : 0;
  }
  if (hex[0] == '\0') {
    return required ? -1 : 0;
  }
  if (decode_hex_string(hex, out_buf, out_buf_cap, out_len) != 0) {
    return -1;
  }
  *out_has_value = 1;
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

static int is_valid_group_name(const char* group_name) {
  size_t len = 0;

  if (group_name == NULL) {
    return 0;
  }

  len = strlen(group_name);
  return len > 0 && len < DB_GROUP_NAME_MAX;
}

static int has_metadata_permission(server_context_t* ctx, int user_id,
                                   const db_file_metadata_t* meta,
                                   int owner_mask, int group_mask,
                                   int other_mask) {
  int is_member = 0;

  if (!ctx || !meta) {
    return 0;
  }
  if (meta->owner_id == user_id && (meta->mode_bits & owner_mask)) {
    return 1;
  }

  if (meta->has_group_id &&
      db_is_user_in_group(ctx, user_id, meta->group_id, &is_member) == 0 &&
      is_member && (meta->mode_bits & group_mask)) {
    return 1;
  }

  return (meta->mode_bits & other_mask) != 0;
}

static int parse_filepath_query(const http_message_t* msg, filepath_query_t* out) {
  static const char prefix[] = "filepath=";
  const char* value = NULL;
  size_t len = 0;

  if (!msg || !out) {
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
  if (len >= sizeof(out->filepath)) {
    return -1;
  }

  memcpy(out->filepath, value, len);
  out->filepath[len] = '\0';
  return is_valid_logical_path(out->filepath) ? 0 : -1;
}

static int can_create_in_directory(server_context_t* ctx, int user_id,
                                   const db_file_metadata_t* parent_meta) {
  if (!ctx || !parent_meta) {
    return 0;
  }
  if (strcmp(parent_meta->object_type, "directory") != 0) {
    return 0;
  }
  return has_metadata_permission(ctx, user_id, parent_meta, 0200, 0020, 0002);
}

static int can_access_file(server_context_t* ctx, int user_id,
                           const db_file_metadata_t* meta, int owner_mask,
                           int group_mask, int other_mask) {
  if (!ctx || !meta) {
    return 0;
  }
  if (strcmp(meta->object_type, "file") != 0) {
    return 0;
  }
  return has_metadata_permission(ctx, user_id, meta, owner_mask, group_mask,
                                 other_mask);
}

static int can_access_directory(server_context_t* ctx, int user_id,
                                const db_file_metadata_t* meta, int owner_mask,
                                int group_mask, int other_mask) {
  if (!ctx || !meta) {
    return 0;
  }
  if (strcmp(meta->object_type, "directory") != 0) {
    return 0;
  }
  return has_metadata_permission(ctx, user_id, meta, owner_mask, group_mask,
                                 other_mask);
}

static int resolve_fek_access_scope(server_context_t* ctx, int user_id,
                                    const db_file_metadata_t* meta,
                                    const unsigned char** out_wrapped_fek,
                                    size_t* out_wrapped_fek_len,
                                    const char** out_scope) {
  int is_member = 0;

  if (!ctx || !meta || !out_wrapped_fek || !out_wrapped_fek_len || !out_scope) {
    return -1;
  }

  if (meta->owner_id == user_id && meta->has_wrapped_fek_owner) {
    *out_wrapped_fek = meta->wrapped_fek_owner;
    *out_wrapped_fek_len = meta->wrapped_fek_owner_len;
    *out_scope = "owner";
    return 0;
  }

  if (meta->has_group_id && meta->has_wrapped_fek_group &&
      db_is_user_in_group(ctx, user_id, meta->group_id, &is_member) == 0 &&
      is_member) {
    *out_wrapped_fek = meta->wrapped_fek_group;
    *out_wrapped_fek_len = meta->wrapped_fek_group_len;
    *out_scope = "group";
    return 0;
  }

  if (meta->has_wrapped_fek_other) {
    *out_wrapped_fek = meta->wrapped_fek_other;
    *out_wrapped_fek_len = meta->wrapped_fek_other_len;
    *out_scope = "other";
    return 0;
  }

  return -1;
}

static int is_subpath_of(const char* parent, const char* candidate) {
  size_t parent_len = 0;

  if (!parent || !candidate) {
    return 0;
  }

  parent_len = strlen(parent);
  if (strncmp(parent, candidate, parent_len) != 0) {
    return 0;
  }

  return candidate[parent_len] == '/' || candidate[parent_len] == '\0';
}

static int rewrite_path_prefix(const char* old_prefix, const char* new_prefix,
                               const char* old_path, char* out,
                               size_t out_sz) {
  int written = 0;
  const char* suffix = NULL;

  if (!old_prefix || !new_prefix || !old_path || !out || out_sz == 0) {
    return -1;
  }
  if (!is_subpath_of(old_prefix, old_path)) {
    return -1;
  }

  suffix = old_path + strlen(old_prefix);
  written = snprintf(out, out_sz, "%s%s", new_prefix, suffix);
  if (written < 0 || (size_t)written >= out_sz) {
    return -1;
  }

  return 0;
}

static int metadata_vec_push(metadata_vec_t* vec,
                             const db_file_metadata_t* metadata) {
  db_file_metadata_t* new_items = NULL;
  size_t new_capacity = 0;

  if (!vec || !metadata) {
    return -1;
  }
  if (vec->count == vec->capacity) {
    new_capacity = vec->capacity == 0 ? 8 : vec->capacity * 2;
    new_items = realloc(vec->items, new_capacity * sizeof(*new_items));
    if (new_items == NULL) {
      return -1;
    }
    vec->items = new_items;
    vec->capacity = new_capacity;
  }

  vec->items[vec->count++] = *metadata;
  return 0;
}

static void metadata_vec_cleanup(metadata_vec_t* vec) {
  if (!vec) {
    return;
  }

  free(vec->items);
  vec->items = NULL;
  vec->count = 0;
  vec->capacity = 0;
}

static int collect_descendants(server_context_t* ctx, const unsigned char* path,
                               size_t path_len, metadata_vec_t* out_vec) {
  db_file_metadata_t* children = NULL;
  size_t child_count = 0;

  if (!ctx || !path || !out_vec) {
    return -1;
  }
  if (db_list_children(ctx, path, path_len, NULL, 0, &child_count) != 0) {
    return -1;
  }
  if (child_count == 0) {
    return 0;
  }

  children = calloc(child_count, sizeof(*children));
  if (children == NULL) {
    return -1;
  }
  if (db_list_children(ctx, path, path_len, children, child_count,
                       &child_count) != 0) {
    free(children);
    return -1;
  }

  for (size_t i = 0; i < child_count; i++) {
    if (metadata_vec_push(out_vec, &children[i]) != 0) {
      free(children);
      return -1;
    }
    if (strcmp(children[i].object_type, "directory") == 0 &&
        collect_descendants(ctx, children[i].path, children[i].path_len,
                            out_vec) != 0) {
      free(children);
      return -1;
    }
  }

  free(children);
  return 0;
}

static int delete_file_metadata_and_backing_file(server_context_t* ctx,
                                                 const char* filepath) {
  int rc = 0;

  if (!ctx || !filepath) {
    return -1;
  }

  if (db_begin_transaction(ctx) != 0) {
    return -1;
  }

  rc = db_delete_file_metadata(ctx, filepath, strlen(filepath));
  if (rc != 1) {
    db_rollback(ctx);
    return rc < 0 ? -1 : 0;
  }

  if (db_commit(ctx) != 0) {
    db_rollback(ctx);
    return -1;
  }

  delete_backing_file(ctx, filepath);
  return 1;
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

static void cleanup_create_directory_request(create_directory_request_t* req) {
  if (!req) {
    return;
  }

  if (req->json) {
    cJSON_Delete(req->json);
  }
  free(req->body);
}

static void cleanup_move_file_request(move_file_request_t* req) {
  if (!req) {
    return;
  }

  if (req->json) {
    cJSON_Delete(req->json);
  }
  free(req->body);
}

static void cleanup_permissions_request(permissions_request_t* req) {
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
  cJSON* group_name_json = NULL;
  cJSON* wrapped_owner_json = NULL;
  cJSON* wrapped_group_json = NULL;
  cJSON* wrapped_other_json = NULL;

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
  if (!out_req->body) {
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
  if (!out_req->json) {
    send_bad_request(response, ssl);
    return -1;
  }

  filepath_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "filepath");
  group_name_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "group_name");
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
  if (group_name_json != NULL &&
      (!cJSON_IsString(group_name_json) || group_name_json->valuestring == NULL ||
       !is_valid_group_name(group_name_json->valuestring))) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid group_name\"}");
    return -1;
  }

  wrapped_owner_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_owner");
  wrapped_group_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_group");
  wrapped_other_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_other");

  if (!cJSON_IsString(wrapped_owner_json) ||
      wrapped_owner_json->valuestring == NULL ||
      wrapped_owner_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"wrapped_fek_owner is required\"}");
    return -1;
  }

  if (wrapped_group_json != NULL && !cJSON_IsString(wrapped_group_json)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_fek_group\"}");
    return -1;
  }
  if (wrapped_other_json != NULL && !cJSON_IsString(wrapped_other_json)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_fek_other\"}");
    return -1;
  }

  out_req->wrapped_fek_owner_hex = wrapped_owner_json->valuestring;
  out_req->group_name =
      group_name_json ? group_name_json->valuestring : NULL;
  out_req->wrapped_fek_group_hex =
      wrapped_group_json ? wrapped_group_json->valuestring : NULL;
  out_req->wrapped_fek_other_hex =
      wrapped_other_json ? wrapped_other_json->valuestring : NULL;

  return 0;
}

static int parse_create_directory_request(http_message_t* msg, SSL* ssl,
                                          http_message_t* response,
                                          create_directory_request_t* out_req,
                                          size_t* out_body_bytes_read) {
  cJSON* dirpath_json = NULL;

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
  if (!out_req->body) {
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
  if (!out_req->json) {
    send_bad_request(response, ssl);
    return -1;
  }

  dirpath_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "dirpath");
  if (!cJSON_IsString(dirpath_json) || dirpath_json->valuestring == NULL) {
    dirpath_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "filepath");
  }
  if (!cJSON_IsString(dirpath_json) || dirpath_json->valuestring == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  out_req->dirpath = dirpath_json->valuestring;
  if (strlen(out_req->dirpath) >= DB_FILE_PATH_MAX ||
      !is_valid_logical_path(out_req->dirpath)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid dirpath\"}");
    return -1;
  }

  return 0;
}

static int parse_move_file_request(http_message_t* msg, SSL* ssl,
                                   http_message_t* response,
                                   move_file_request_t* out_req,
                                   size_t* out_body_bytes_read) {
  cJSON* source_json = NULL;
  cJSON* dest_json = NULL;

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
  if (!out_req->body) {
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
  if (!out_req->json) {
    send_bad_request(response, ssl);
    return -1;
  }

  source_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "source_filepath");
  dest_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "destination_filepath");
  if (!cJSON_IsString(source_json) || source_json->valuestring == NULL ||
      !cJSON_IsString(dest_json) || dest_json->valuestring == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  out_req->source_filepath = source_json->valuestring;
  out_req->destination_filepath = dest_json->valuestring;
  if (strlen(out_req->source_filepath) >= DB_FILE_PATH_MAX ||
      strlen(out_req->destination_filepath) >= DB_FILE_PATH_MAX ||
      !is_valid_logical_path(out_req->source_filepath) ||
      !is_valid_logical_path(out_req->destination_filepath) ||
      strcmp(out_req->source_filepath, out_req->destination_filepath) == 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid move request\"}");
    return -1;
  }

  return 0;
}

static int parse_mode_bits_json(cJSON* mode_json, int* out_mode_bits) {
  char* endptr = NULL;
  long mode = 0;

  if (!mode_json || !out_mode_bits) {
    return -1;
  }
  if (cJSON_IsNumber(mode_json)) {
    mode = (long)mode_json->valuedouble;
  } else if (cJSON_IsString(mode_json) && mode_json->valuestring != NULL) {
    errno = 0;
    mode = strtol(mode_json->valuestring, &endptr, 8);
    if (errno != 0 || endptr == mode_json->valuestring || *endptr != '\0') {
      return -1;
    }
  } else {
    return -1;
  }

  if (mode < 0 || mode > 0777) {
    return -1;
  }

  *out_mode_bits = (int)mode;
  return 0;
}

static int parse_permissions_request(http_message_t* msg, SSL* ssl,
                                     http_message_t* response,
                                     permissions_request_t* out_req,
                                     size_t* out_body_bytes_read) {
  cJSON* filepath_json = NULL;
  cJSON* mode_bits_json = NULL;
  cJSON* wrapped_owner_json = NULL;
  cJSON* wrapped_group_json = NULL;
  cJSON* wrapped_other_json = NULL;

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
  if (!out_req->body) {
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
  if (!out_req->json) {
    send_bad_request(response, ssl);
    return -1;
  }

  filepath_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "filepath");
  mode_bits_json = cJSON_GetObjectItemCaseSensitive(out_req->json, "mode_bits");
  wrapped_owner_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_owner");
  wrapped_group_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_group");
  wrapped_other_json =
      cJSON_GetObjectItemCaseSensitive(out_req->json, "wrapped_fek_other");
  if (!cJSON_IsString(filepath_json) || filepath_json->valuestring == NULL) {
    send_bad_request(response, ssl);
    return -1;
  }

  if (wrapped_owner_json != NULL && !cJSON_IsString(wrapped_owner_json)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_fek_owner\"}");
    return -1;
  }
  if (wrapped_group_json != NULL && !cJSON_IsString(wrapped_group_json)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_fek_group\"}");
    return -1;
  }
  if (wrapped_other_json != NULL && !cJSON_IsString(wrapped_other_json)) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid wrapped_fek_other\"}");
    return -1;
  }

  out_req->filepath = filepath_json->valuestring;
  out_req->wrapped_fek_owner_hex =
      wrapped_owner_json ? wrapped_owner_json->valuestring : NULL;
  out_req->wrapped_fek_group_hex =
      wrapped_group_json ? wrapped_group_json->valuestring : NULL;
  out_req->wrapped_fek_other_hex =
      wrapped_other_json ? wrapped_other_json->valuestring : NULL;
  if (strlen(out_req->filepath) >= DB_FILE_PATH_MAX ||
      !is_valid_logical_path(out_req->filepath) ||
      parse_mode_bits_json(mode_bits_json, &out_req->mode_bits) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid filepath or mode_bits\"}");
    return -1;
  }

  return 0;
}

static int populate_new_file_metadata(const create_file_request_t* req,
                                      const char* file_name,
                                      const server_session_t* session,
                                      const db_file_metadata_t* parent_meta,
                                      db_file_metadata_t* out_meta) {
  size_t filepath_len = 0;
  size_t file_name_len = 0;
  long long now = 0;

  if (!req || !req->filepath || !file_name || !session || !parent_meta ||
      !out_meta) {
    return -1;
  }

  filepath_len = strlen(req->filepath);
  file_name_len = strlen(file_name);
  now = (long long)time(NULL);

  memset(out_meta, 0, sizeof(*out_meta));
  memcpy(out_meta->path, req->filepath, filepath_len);
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

  if (set_wrapped_fek_from_hex(req->wrapped_fek_owner_hex, 1,
                               out_meta->wrapped_fek_owner,
                               sizeof(out_meta->wrapped_fek_owner),
                               &out_meta->wrapped_fek_owner_len,
                               &out_meta->has_wrapped_fek_owner) != 0 ||
      set_wrapped_fek_from_hex(req->wrapped_fek_group_hex, 0,
                               out_meta->wrapped_fek_group,
                               sizeof(out_meta->wrapped_fek_group),
                               &out_meta->wrapped_fek_group_len,
                               &out_meta->has_wrapped_fek_group) != 0 ||
      set_wrapped_fek_from_hex(req->wrapped_fek_other_hex, 0,
                               out_meta->wrapped_fek_other,
                               sizeof(out_meta->wrapped_fek_other),
                               &out_meta->wrapped_fek_other_len,
                               &out_meta->has_wrapped_fek_other) != 0) {
    return -1;
  }

  if (out_meta->has_group_id && (out_meta->mode_bits & 0070) != 0 &&
      !out_meta->has_wrapped_fek_group) {
    return -1;
  }
  if ((out_meta->mode_bits & 0007) != 0 && !out_meta->has_wrapped_fek_other) {
    return -1;
  }

  return 0;
}

static int apply_wrapped_feks_for_mode_bits(const permissions_request_t* req,
                                            db_file_metadata_t* meta) {
  int group_enabled = 0;
  int other_enabled = 0;

  if (!req || !meta) {
    return -1;
  }

  if (req->wrapped_fek_owner_hex != NULL &&
      set_wrapped_fek_from_hex(req->wrapped_fek_owner_hex, 1,
                               meta->wrapped_fek_owner,
                               sizeof(meta->wrapped_fek_owner),
                               &meta->wrapped_fek_owner_len,
                               &meta->has_wrapped_fek_owner) != 0) {
    return -1;
  }
  if (!meta->has_wrapped_fek_owner) {
    return -1;
  }

  group_enabled = meta->has_group_id && ((req->mode_bits & 0070) != 0);
  other_enabled = (req->mode_bits & 0007) != 0;

  if (group_enabled) {
    if (req->wrapped_fek_group_hex != NULL &&
        set_wrapped_fek_from_hex(req->wrapped_fek_group_hex, 1,
                                 meta->wrapped_fek_group,
                                 sizeof(meta->wrapped_fek_group),
                                 &meta->wrapped_fek_group_len,
                                 &meta->has_wrapped_fek_group) != 0) {
      return -1;
    }
    if (!meta->has_wrapped_fek_group) {
      return -1;
    }
  } else {
    meta->has_wrapped_fek_group = 0;
    meta->wrapped_fek_group_len = 0;
    memset(meta->wrapped_fek_group, 0, sizeof(meta->wrapped_fek_group));
  }

  if (other_enabled) {
    if (req->wrapped_fek_other_hex != NULL &&
        set_wrapped_fek_from_hex(req->wrapped_fek_other_hex, 1,
                                 meta->wrapped_fek_other,
                                 sizeof(meta->wrapped_fek_other),
                                 &meta->wrapped_fek_other_len,
                                 &meta->has_wrapped_fek_other) != 0) {
      return -1;
    }
    if (!meta->has_wrapped_fek_other) {
      return -1;
    }
  } else {
    meta->has_wrapped_fek_other = 0;
    meta->wrapped_fek_other_len = 0;
    memset(meta->wrapped_fek_other, 0, sizeof(meta->wrapped_fek_other));
  }

  return 0;
}

static int populate_new_directory_metadata(
    const char* dirpath, const char* dir_name, const server_session_t* session,
    const db_file_metadata_t* parent_meta, db_file_metadata_t* out_meta) {
  size_t dirpath_len = 0;
  size_t dir_name_len = 0;
  long long now = 0;

  if (!dirpath || !dir_name || !session || !parent_meta || !out_meta) {
    return -1;
  }

  dirpath_len = strlen(dirpath);
  dir_name_len = strlen(dir_name);
  now = (long long)time(NULL);

  memset(out_meta, 0, sizeof(*out_meta));
  memcpy(out_meta->path, dirpath, dirpath_len);
  out_meta->path_len = dirpath_len;
  memcpy(out_meta->name, dir_name, dir_name_len);
  out_meta->name_len = dir_name_len;
  out_meta->owner_id = session->user_id;
  out_meta->group_id = parent_meta->group_id;
  out_meta->has_group_id = parent_meta->has_group_id;
  out_meta->mode_bits = 0750;
  strncpy(out_meta->object_type, "directory",
          sizeof(out_meta->object_type) - 1);
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

static int create_directory_metadata_and_backing_dir(
    server_context_t* ctx, const db_file_metadata_t* meta, int* out_metadata_id) {
  if (db_begin_transaction(ctx) != 0) {
    return -1;
  }

  if (db_create_file_metadata(ctx, meta, out_metadata_id) != 0) {
    db_rollback(ctx);
    return -1;
  }

  if (create_directory_ctx(ctx, (const char*)meta->path) != 0) {
    db_rollback(ctx);
    return -1;
  }

  if (db_commit(ctx) != 0) {
    db_rollback(ctx);
    return -1;
  }

  return 0;
}

static int update_single_metadata_path(server_context_t* ctx,
                                       const db_file_metadata_t* source_meta,
                                       const char* current_path,
                                       const char* new_path) {
  db_file_metadata_t updated = *source_meta;
  const char* last_slash = NULL;
  size_t new_path_len = 0;
  size_t name_len = 0;

  if (!ctx || !source_meta || !current_path || !new_path) {
    return -1;
  }
  last_slash = strrchr(new_path, '/');
  if (!last_slash || *(last_slash + 1) == '\0') {
    return -1;
  }
  new_path_len = strlen(new_path);
  name_len = strlen(last_slash + 1);
  if (new_path_len >= sizeof(updated.path) || name_len >= sizeof(updated.name)) {
    return -1;
  }

  memset(updated.path, 0, sizeof(updated.path));
  memcpy(updated.path, new_path, new_path_len);
  updated.path_len = new_path_len;
  memset(updated.name, 0, sizeof(updated.name));
  memcpy(updated.name, last_slash + 1, name_len);
  updated.name_len = name_len;
  updated.updated_at = (long long)time(NULL);

  return db_update_file_metadata(ctx, current_path, strlen(current_path),
                                 &updated);
}

static int apply_directory_move_metadata(server_context_t* ctx,
                                         const db_file_metadata_t* source_meta,
                                         const char* new_path) {
  metadata_vec_t descendants = {0};
  char source_path[DB_FILE_PATH_MAX];
  char current_path[DB_FILE_PATH_MAX];
  char rewritten_path[DB_FILE_PATH_MAX];

  if (!ctx || !source_meta || !new_path) {
    return -1;
  }
  if (blob_to_cstring(source_meta->path, source_meta->path_len, source_path,
                      sizeof(source_path)) != 0) {
    return -1;
  }

  if (collect_descendants(ctx, source_meta->path, source_meta->path_len,
                          &descendants) != 0) {
    metadata_vec_cleanup(&descendants);
    return -1;
  }

  if (db_begin_transaction(ctx) != 0) {
    metadata_vec_cleanup(&descendants);
    return -1;
  }

  if (update_single_metadata_path(ctx, source_meta, source_path, new_path) < 0) {
    db_rollback(ctx);
    metadata_vec_cleanup(&descendants);
    return -1;
  }

  for (size_t i = 0; i < descendants.count; i++) {
    if (blob_to_cstring(descendants.items[i].path, descendants.items[i].path_len,
                        current_path, sizeof(current_path)) != 0 ||
        rewrite_path_prefix(source_path, new_path, current_path, rewritten_path,
                            sizeof(rewritten_path)) != 0 ||
        update_single_metadata_path(ctx, &descendants.items[i], current_path,
                                    rewritten_path) < 0) {
      db_rollback(ctx);
      metadata_vec_cleanup(&descendants);
      return -1;
    }
  }

  metadata_vec_cleanup(&descendants);
  return 0;
}

static int finalize_move_transaction(server_context_t* ctx, const char* old_path,
                                     const char* new_path) {
  if (rename_storage_path(ctx, old_path, new_path) != 0) {
    db_rollback(ctx);
    return -1;
  }

  if (db_commit(ctx) != 0) {
    rename_storage_path(ctx, new_path, old_path);
    db_rollback(ctx);
    return -1;
  }

  return 0;
}

static int append_entry_json(cJSON* entries, const db_file_metadata_t* meta) {
  cJSON* item = NULL;
  char path[DB_FILE_PATH_MAX];
  char name[DB_FILE_NAME_MAX];

  if (!entries || !meta) {
    return -1;
  }
  if (blob_to_cstring(meta->path, meta->path_len, path, sizeof(path)) != 0 ||
      blob_to_cstring(meta->name, meta->name_len, name, sizeof(name)) != 0) {
    return -1;
  }

  item = cJSON_CreateObject();
  if (item == NULL) {
    return -1;
  }

  cJSON_AddStringToObject(item, "path", path);
  cJSON_AddStringToObject(item, "name", name);
  cJSON_AddStringToObject(item, "object_type", meta->object_type);
  cJSON_AddNumberToObject(item, "owner_id", meta->owner_id);
  if (meta->has_group_id) {
    cJSON_AddNumberToObject(item, "group_id", meta->group_id);
  } else {
    cJSON_AddNullToObject(item, "group_id");
  }
  cJSON_AddNumberToObject(item, "mode_bits", meta->mode_bits);
  cJSON_AddNumberToObject(item, "created_at", (double)meta->created_at);
  cJSON_AddNumberToObject(item, "updated_at", (double)meta->updated_at);
  cJSON_AddItemToArray(entries, item);
  return 0;
}

void create_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx) {
  create_file_request_t req = {0};
  char parent_path[DB_FILE_PATH_MAX];
  char file_name[DB_FILE_NAME_MAX];
  server_session_t session;
  db_group_t selected_group;
  db_file_metadata_t parent_meta;
  db_file_metadata_t existing_meta;
  db_file_metadata_t new_meta;
  int is_group_member = 0;
  size_t body_bytes_read = 0;
  int metadata_id = 0;
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

  if (populate_new_file_metadata(&req, file_name, &session, &parent_meta,
                                 &new_meta) != 0) {
    send_json_error(
        ssl, response, 400, "Bad Request",
        "{\"error\":\"wrapped FEKs do not match the selected file access\"}");
    goto cleanup;
  }

  if (req.group_name != NULL) {
    rc = db_find_group_by_name(ctx, req.group_name, &selected_group);
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

    if (db_is_user_in_group(ctx, session.user_id, selected_group.id,
                            &is_group_member) != 0) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"failed to verify group membership\"}");
      goto cleanup;
    }
    if (!is_group_member) {
      send_json_error(ssl, response, 403, "Forbidden",
                      "{\"error\":\"user is not a member of the requested group\"}");
      goto cleanup;
    }

    new_meta.group_id = selected_group.id;
    new_meta.has_group_id = 1;
    if ((new_meta.mode_bits & 0070) != 0 && !new_meta.has_wrapped_fek_group) {
      send_json_error(
          ssl, response, 400, "Bad Request",
          "{\"error\":\"wrapped_fek_group is required when group access is enabled\"}");
      goto cleanup;
    }
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
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_create_file_request(&req);
}

void create_directory(http_message_t* msg, SSL* ssl,
                      http_message_t* response, server_context_t* ctx) {
  create_directory_request_t req = {0};
  char parent_path[DB_FILE_PATH_MAX];
  char dir_name[DB_FILE_NAME_MAX];
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
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (parse_create_directory_request(msg, ssl, response, &req,
                                     &body_bytes_read) != 0) {
    goto cleanup;
  }
  if (split_parent_child(req.dirpath, parent_path, sizeof(parent_path),
                         dir_name, sizeof(dir_name)) != 0) {
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

  rc = db_find_file_metadata_by_path(ctx, req.dirpath, strlen(req.dirpath),
                                     &existing_meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to check existing directory\"}");
    goto cleanup;
  }
  if (rc == 1) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"path already exists\"}");
    goto cleanup;
  }

  if (populate_new_directory_metadata(req.dirpath, dir_name, &session,
                                      &parent_meta, &new_meta) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build directory metadata\"}");
    goto cleanup;
  }
  if (create_directory_metadata_and_backing_dir(ctx, &new_meta, &metadata_id) !=
      0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create directory\"}");
    goto cleanup;
  }

  {
    char resp[CREATE_FILE_RESPONSE_MAX];
    int n = snprintf(resp, sizeof(resp),
                     "{\"message\":\"directory created\",\"dirpath\":\"%s\","
                     "\"directory_id\":%d}",
                     req.dirpath, metadata_id);
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
  cleanup_create_directory_request(&req);
}

void get_files(http_message_t* msg, SSL* ssl, http_message_t* response,
               server_context_t* ctx) {
  filepath_query_t query = {0};
  server_session_t session;
  db_file_metadata_t directory_meta;
  db_file_metadata_t* children = NULL;
  cJSON* root = NULL;
  cJSON* entries = NULL;
  char* json = NULL;
  size_t child_count = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (parse_filepath_query(msg, &query) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"missing or invalid filepath query\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = db_find_file_metadata_by_path(ctx, query.filepath, strlen(query.filepath),
                                     &directory_meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load directory metadata\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"directory not found\"}");
    return;
  }
  if (strcmp(directory_meta.object_type, "directory") != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"filepath is not a directory\"}");
    return;
  }
  if (!can_access_directory(ctx, session.user_id, &directory_meta, 0400, 0040,
                            0004)) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    return;
  }

  if (db_list_children(ctx, query.filepath, strlen(query.filepath), NULL, 0,
                       &child_count) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to list directory\"}");
    return;
  }
  if (child_count > 0) {
    children = calloc(child_count, sizeof(*children));
    if (children == NULL) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"allocation failure\"}");
      return;
    }
    if (db_list_children(ctx, query.filepath, strlen(query.filepath), children,
                         child_count, &child_count) != 0) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"failed to list directory\"}");
      goto cleanup;
    }
  }

  root = cJSON_CreateObject();
  if (root == NULL) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"response build failure\"}");
    goto cleanup;
  }
  cJSON_AddStringToObject(root, "directory", query.filepath);
  entries = cJSON_AddArrayToObject(root, "entries");
  if (entries == NULL) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"response build failure\"}");
    goto cleanup;
  }

  for (size_t i = 0; i < child_count; i++) {
    if (append_entry_json(entries, &children[i]) != 0) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"response build failure\"}");
      goto cleanup;
    }
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
  free(children);
}

void get_file_metadata(http_message_t* msg, SSL* ssl, http_message_t* response,
                       server_context_t* ctx) {
  filepath_query_t query = {0};
  server_session_t session;
  db_file_metadata_t meta;
  cJSON* root = NULL;
  char* json = NULL;
  char path[DB_FILE_PATH_MAX];
  char name[DB_FILE_NAME_MAX];
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }
  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (parse_filepath_query(msg, &query) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"missing or invalid filepath query\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = db_find_file_metadata_by_path(ctx, query.filepath, strlen(query.filepath),
                                     &meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load metadata\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"path not found\"}");
    return;
  }

  if ((strcmp(meta.object_type, "directory") == 0 &&
       !can_access_directory(ctx, session.user_id, &meta, 0400, 0040, 0004)) ||
      (strcmp(meta.object_type, "file") == 0 &&
       !can_access_file(ctx, session.user_id, &meta, 0400, 0040, 0004))) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    return;
  }

  if (blob_to_cstring(meta.path, meta.path_len, path, sizeof(path)) != 0 ||
      blob_to_cstring(meta.name, meta.name_len, name, sizeof(name)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to prepare metadata response\"}");
    return;
  }

  root = cJSON_CreateObject();
  if (root == NULL) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"response build failure\"}");
    return;
  }

  cJSON_AddStringToObject(root, "path", path);
  cJSON_AddStringToObject(root, "name", name);
  cJSON_AddStringToObject(root, "object_type", meta.object_type);
  cJSON_AddNumberToObject(root, "owner_id", meta.owner_id);
  if (meta.has_group_id) {
    cJSON_AddNumberToObject(root, "group_id", meta.group_id);
  } else {
    cJSON_AddNullToObject(root, "group_id");
  }
  cJSON_AddNumberToObject(root, "mode_bits", meta.mode_bits);
  cJSON_AddNumberToObject(root, "created_at", (double)meta.created_at);
  cJSON_AddNumberToObject(root, "updated_at", (double)meta.updated_at);

  json = cJSON_PrintUnformatted(root);
  if (json == NULL) {
    cJSON_Delete(root);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"response build failure\"}");
    return;
  }

  set_json_response(response, 200, "OK", strlen(json));
  send_response(ssl, response);
  write_json_body(ssl, json);

  free(json);
  cJSON_Delete(root);
}

void move_file(http_message_t* msg, SSL* ssl, http_message_t* response,
               server_context_t* ctx) {
  move_file_request_t req = {0};
  server_session_t session;
  db_file_metadata_t source_meta;
  db_file_metadata_t destination_parent_meta;
  db_file_metadata_t existing_meta;
  char destination_parent[DB_FILE_PATH_MAX];
  char destination_name[DB_FILE_NAME_MAX];
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
  if (parse_move_file_request(msg, ssl, response, &req, &body_bytes_read) !=
      0) {
    goto cleanup;
  }
  if (split_parent_child(req.destination_filepath, destination_parent,
                         sizeof(destination_parent), destination_name,
                         sizeof(destination_name)) != 0) {
    send_bad_request(response, ssl);
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, req.source_filepath,
                                     strlen(req.source_filepath), &source_meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load source metadata\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"source path not found\"}");
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, destination_parent,
                                     strlen(destination_parent),
                                     &destination_parent_meta);
  if (rc != 1) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"destination parent not found\"}");
    goto cleanup;
  }
  if (!can_create_in_directory(ctx, session.user_id, &destination_parent_meta)) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    goto cleanup;
  }

  if (strcmp(source_meta.object_type, "file") == 0) {
    if (!can_access_file(ctx, session.user_id, &source_meta, 0200, 0020,
                         0002)) {
      send_json_error(ssl, response, 403, "Forbidden",
                      "{\"error\":\"insufficient permissions\"}");
      goto cleanup;
    }
  } else if (strcmp(source_meta.object_type, "directory") == 0) {
    if (!can_access_directory(ctx, session.user_id, &source_meta, 0200, 0020,
                              0002)) {
      send_json_error(ssl, response, 403, "Forbidden",
                      "{\"error\":\"insufficient permissions\"}");
      goto cleanup;
    }
    if (is_subpath_of(req.source_filepath, req.destination_filepath)) {
      send_json_error(ssl, response, 400, "Bad Request",
                      "{\"error\":\"cannot move a directory inside itself\"}");
      goto cleanup;
    }
  }

  rc = db_find_file_metadata_by_path(ctx, req.destination_filepath,
                                     strlen(req.destination_filepath),
                                     &existing_meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to check destination path\"}");
    goto cleanup;
  }
  if (rc == 1) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"destination path already exists\"}");
    goto cleanup;
  }

  if (strcmp(source_meta.object_type, "directory") == 0) {
    if (apply_directory_move_metadata(ctx, &source_meta,
                                      req.destination_filepath) != 0) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"failed to update directory metadata\"}");
      goto cleanup;
    }
  } else {
    if (db_begin_transaction(ctx) != 0 ||
        update_single_metadata_path(ctx, &source_meta, req.source_filepath,
                                    req.destination_filepath) < 0) {
      db_rollback(ctx);
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"failed to update file metadata\"}");
      goto cleanup;
    }
  }

  if (finalize_move_transaction(ctx, req.source_filepath,
                                req.destination_filepath) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to move storage path\"}");
    goto cleanup;
  }

  {
    char resp[CREATE_FILE_RESPONSE_MAX];
    int n = snprintf(resp, sizeof(resp),
                     "{\"message\":\"path moved\",\"from\":\"%s\","
                     "\"to\":\"%s\"}",
                     req.source_filepath, req.destination_filepath);
    if (n < 0 || (size_t)n >= sizeof(resp)) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"response build failure\"}");
      goto cleanup;
    }

    set_json_response(response, 200, "OK", (size_t)n);
    send_response(ssl, response);
    write_json_body(ssl, resp);
  }

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_move_file_request(&req);
}

void update_file_permissions(http_message_t* msg, SSL* ssl,
                             http_message_t* response,
                             server_context_t* ctx) {
  permissions_request_t req = {0};
  server_session_t session;
  db_file_metadata_t meta;
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
  if (parse_permissions_request(msg, ssl, response, &req, &body_bytes_read) !=
      0) {
    goto cleanup;
  }

  rc = db_find_file_metadata_by_path(ctx, req.filepath, strlen(req.filepath),
                                     &meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load metadata\"}");
    goto cleanup;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"path not found\"}");
    goto cleanup;
  }
  if (meta.owner_id != session.user_id) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"only the owner can update permissions\"}");
    goto cleanup;
  }

  meta.mode_bits = req.mode_bits;
  if (apply_wrapped_feks_for_mode_bits(&req, &meta) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"wrapped FEKs do not match requested permissions\"}");
    goto cleanup;
  }
  meta.updated_at = (long long)time(NULL);
  rc = db_update_file_metadata(ctx, req.filepath, strlen(req.filepath), &meta);
  if (rc < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to update permissions\"}");
    goto cleanup;
  }

  {
    char resp[256];
    int n = snprintf(resp, sizeof(resp),
                     "{\"message\":\"permissions updated\",\"filepath\":\"%s\","
                     "\"mode_bits\":%d}",
                     req.filepath, req.mode_bits);
    if (n < 0 || (size_t)n >= sizeof(resp)) {
      send_json_error(ssl, response, 500, "Internal Server Error",
                      "{\"error\":\"response build failure\"}");
      goto cleanup;
    }

    set_json_response(response, 200, "OK", (size_t)n);
    send_response(ssl, response);
    write_json_body(ssl, resp);
  }

cleanup:
  if (body_bytes_read < msg->content_length) {
    drain_message_body(ssl, msg, msg->content_length - body_bytes_read);
  }
  cleanup_permissions_request(&req);
}

void write_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                server_context_t* ctx) {
  filepath_query_t query = {0};
  server_session_t session;
  db_file_metadata_t meta;
  char storage_path[STORAGE_PATH_MAX];
  char* body = NULL;
  int fd = -1;
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
  if (parse_filepath_query(msg, &query) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"missing or invalid filepath query\"}");
    return;
  }
  if (msg->content_length > HTTP_MAX_BODY_LEN) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"content too large\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = db_find_file_metadata_by_path(ctx, query.filepath, strlen(query.filepath),
                                     &meta);
  if (rc == -1) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load file metadata\"}");
    return;
  }
  if (rc == 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"file not found\"}");
    return;
  }
  if (!can_access_file(ctx, session.user_id, &meta, 0200, 0020, 0002)) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    return;
  }
  if (build_storage_path(ctx, query.filepath, storage_path,
                         sizeof(storage_path)) != 0) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build storage path\"}");
    return;
  }

  body = calloc(msg->content_length + 1, 1);
  if (body == NULL) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"allocation failure\"}");
    return;
  }
  if (msg->content_length > 0 &&
      read_exact_body(msg, ssl, body, msg->content_length) != 0) {
    send_bad_request(response, ssl);
    goto cleanup;
  }

  fd = open(storage_path, O_WRONLY | O_TRUNC | O_CREAT, 0644);
  if (fd < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to open backing file\"}");
    goto cleanup;
  }
  if (msg->content_length > 0 &&
      write(fd, body, msg->content_length) != (ssize_t)msg->content_length) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to write backing file\"}");
    goto cleanup;
  }
  close(fd);
  fd = -1;

  meta.updated_at = (long long)time(NULL);
  rc = db_update_file_metadata(ctx, query.filepath, strlen(query.filepath),
                               &meta);
  if (rc < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to update metadata timestamp\"}");
    goto cleanup;
  }

  send_json_error(ssl, response, 200, "OK",
                  "{\"message\":\"file written\"}");

cleanup:
  if (fd >= 0) {
    close(fd);
  }
  free(body);
}

void read_file(http_message_t* msg, SSL* ssl, http_message_t* response,
               server_context_t* ctx) {
  filepath_query_t query = {0};
  server_session_t session;
  db_file_metadata_t meta;
  const unsigned char* selected_wrapped_fek = NULL;
  size_t selected_wrapped_fek_len = 0;
  const char* fek_scope = NULL;
  char wrapped_fek_hex[HTTP_MAX_HEADER_VALUE];
  char storage_path[STORAGE_PATH_MAX];
  char buf[1024];
  struct stat st;
  int fd = -1;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (parse_filepath_query(msg, &query) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"missing or invalid filepath query\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = db_find_file_metadata_by_path(ctx, query.filepath, strlen(query.filepath),
                                     &meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load file metadata\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"file not found\"}");
    return;
  }
  if (!can_access_file(ctx, session.user_id, &meta, 0400, 0040, 0004)) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    return;
  }
  if (resolve_fek_access_scope(ctx, session.user_id, &meta, &selected_wrapped_fek,
                               &selected_wrapped_fek_len, &fek_scope) != 0 ||
      encode_hex_string(selected_wrapped_fek, selected_wrapped_fek_len,
                        wrapped_fek_hex, sizeof(wrapped_fek_hex)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to resolve wrapped FEK\"}");
    return;
  }
  if (build_storage_path(ctx, query.filepath, storage_path,
                         sizeof(storage_path)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build storage path\"}");
    return;
  }

  fd = open(storage_path, O_RDONLY);
  if (fd < 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"backing file not found\"}");
    return;
  }
  if (fstat(fd, &st) != 0 || st.st_size < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to stat backing file\"}");
    close(fd);
    return;
  }

  response->status_code = 200;
  strncpy(response->reason, "OK", sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  response->content_type = STREAM;
  response->content_length = (size_t)st.st_size;
  strncpy(response->connection, "close", sizeof(response->connection) - 1);
  response->connection[sizeof(response->connection) - 1] = '\0';
  strncpy(response->x_wrapped_fek, wrapped_fek_hex,
          sizeof(response->x_wrapped_fek) - 1);
  response->x_wrapped_fek[sizeof(response->x_wrapped_fek) - 1] = '\0';
  strncpy(response->x_fek_scope, fek_scope, sizeof(response->x_fek_scope) - 1);
  response->x_fek_scope[sizeof(response->x_fek_scope) - 1] = '\0';
  send_response(ssl, response);

  while (1) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      break;
    }
    if (n == 0) {
      break;
    }
    if (tls_write(ssl, buf, (size_t)n) != n) {
      break;
    }
  }

  close(fd);
}

void delete_file(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx) {
  filepath_query_t query = {0};
  server_session_t session;
  db_file_metadata_t meta;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }
  if (parse_filepath_query(msg, &query) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"missing or invalid filepath query\"}");
    return;
  }
  if (get_user_from_token(ctx, msg->auth_token, &session) != 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  rc = db_find_file_metadata_by_path(ctx, query.filepath, strlen(query.filepath),
                                     &meta);
  if (rc == -1) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to load file metadata\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"file not found\"}");
    return;
  }
  if (strcmp(meta.object_type, "file") != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"filepath is not a file\"}");
    return;
  }
  if (!can_access_file(ctx, session.user_id, &meta, 0200, 0020, 0002)) {
    send_json_error(ssl, response, 403, "Forbidden",
                    "{\"error\":\"insufficient permissions\"}");
    return;
  }

  rc = delete_file_metadata_and_backing_file(ctx, query.filepath);
  if (rc < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to delete file\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"file not found\"}");
    return;
  }

  send_json_error(ssl, response, 200, "OK",
                  "{\"message\":\"file deleted\"}");
}
