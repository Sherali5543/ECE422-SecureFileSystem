#include "db.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "schema_helper.h"

static int prepare_statement(sqlite3* db, sqlite3_stmt** stmt,
                             const char* sql) {
  if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "db: failed to prepare statement: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

static int finish_statement(sqlite3_stmt* stmt, int rc) {
  if (stmt != NULL) {
    sqlite3_finalize(stmt);
  }
  return rc;
}

static int exec_sql_statement(sqlite3* db, const char* sql,
                              const char* label) {
  if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
    fprintf(stderr, "%s: %s\n", label, sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

static int bind_text_value(sqlite3* db, sqlite3_stmt* stmt, int index,
                           const char* value, const char* label) {
  if (value == NULL) {
    fprintf(stderr, "%s: null text value\n", label);
    return -1;
  }

  if (sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT) !=
      SQLITE_OK) {
    fprintf(stderr, "%s: bind failed: %s\n", label, sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

static int bind_int_value(sqlite3* db, sqlite3_stmt* stmt, int index, int value,
                          const char* label) {
  if (sqlite3_bind_int(stmt, index, value) != SQLITE_OK) {
    fprintf(stderr, "%s: bind failed: %s\n", label, sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

static int bind_blob_value(sqlite3* db, sqlite3_stmt* stmt, int index,
                           const void* value, size_t value_len,
                           const char* label) {
  if (value_len > (size_t)INT_MAX) {
    fprintf(stderr, "%s: blob too large\n", label);
    return -1;
  }

  if (value_len > 0 && value == NULL) {
    fprintf(stderr, "%s: null blob value\n", label);
    return -1;
  }

  if ((value_len == 0 &&
       sqlite3_bind_zeroblob(stmt, index, 0) != SQLITE_OK) ||
      (value_len > 0 &&
       sqlite3_bind_blob(stmt, index, value, (int)value_len,
                         SQLITE_TRANSIENT) != SQLITE_OK)) {
    fprintf(stderr, "%s: bind failed: %s\n", label, sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

static int bind_nullable_blob_value(sqlite3* db, sqlite3_stmt* stmt, int index,
                                    int has_value, const void* value,
                                    size_t value_len, const char* label) {
  if (!has_value) {
    if (sqlite3_bind_null(stmt, index) != SQLITE_OK) {
      fprintf(stderr, "%s: bind failed: %s\n", label, sqlite3_errmsg(db));
      return -1;
    }
    return 0;
  }

  return bind_blob_value(db, stmt, index, value, value_len, label);
}

static int bind_nullable_int_value(sqlite3* db, sqlite3_stmt* stmt, int index,
                                   int has_value, int value,
                                   const char* label) {
  if (!has_value) {
    if (sqlite3_bind_null(stmt, index) != SQLITE_OK) {
      fprintf(stderr, "%s: bind failed: %s\n", label, sqlite3_errmsg(db));
      return -1;
    }
    return 0;
  }

  return bind_int_value(db, stmt, index, value, label);
}

static int copy_text_value(const unsigned char* value, int value_len,
                           char* dest, size_t dest_size, const char* label) {
  if (value == NULL || value_len < 0 || (size_t)value_len >= dest_size) {
    fprintf(stderr, "%s: invalid text value\n", label);
    return -1;
  }

  memcpy(dest, value, (size_t)value_len);
  dest[value_len] = '\0';
  return 0;
}

static int copy_blob_value(const void* value, int value_len,
                           unsigned char* dest, size_t dest_size,
                           size_t* out_len, const char* label) {
  if (value_len < 0 || (size_t)value_len > dest_size) {
    fprintf(stderr, "%s: invalid blob length\n", label);
    return -1;
  }

  if (value_len > 0 && value == NULL) {
    fprintf(stderr, "%s: invalid blob data\n", label);
    return -1;
  }

  if (value_len > 0) {
    memcpy(dest, value, (size_t)value_len);
  }
  *out_len = (size_t)value_len;
  return 0;
}

static int load_user_from_stmt(sqlite3_stmt* stmt, db_user_t* out_user) {
  const unsigned char* db_username = NULL;
  const unsigned char* db_password_hash = NULL;
  const void* db_public_key = NULL;
  int username_len = 0;
  int password_hash_len = 0;
  int public_key_len = 0;

  if (out_user == NULL) {
    return -1;
  }

  memset(out_user, 0, sizeof(*out_user));
  out_user->id = sqlite3_column_int(stmt, 0);

  db_username = sqlite3_column_text(stmt, 1);
  username_len = sqlite3_column_bytes(stmt, 1);
  db_password_hash = sqlite3_column_text(stmt, 2);
  password_hash_len = sqlite3_column_bytes(stmt, 2);
  db_public_key = sqlite3_column_blob(stmt, 3);
  public_key_len = sqlite3_column_bytes(stmt, 3);

  if (copy_text_value(db_username, username_len, out_user->username,
                      sizeof(out_user->username), "load_user_from_stmt") != 0 ||
      copy_text_value(db_password_hash, password_hash_len,
                      out_user->password_hash,
                      sizeof(out_user->password_hash),
                      "load_user_from_stmt") != 0 ||
      copy_blob_value(db_public_key, public_key_len, out_user->public_key,
                      sizeof(out_user->public_key), &out_user->public_key_len,
                      "load_user_from_stmt") != 0) {
    return -1;
  }

  return 0;
}

static int load_group_from_stmt(sqlite3_stmt* stmt, db_group_t* out_group) {
  const unsigned char* db_group_name = NULL;
  int group_name_len = 0;

  if (out_group == NULL) {
    return -1;
  }

  memset(out_group, 0, sizeof(*out_group));
  out_group->id = sqlite3_column_int(stmt, 0);
  db_group_name = sqlite3_column_text(stmt, 1);
  group_name_len = sqlite3_column_bytes(stmt, 1);

  return copy_text_value(db_group_name, group_name_len, out_group->name,
                         sizeof(out_group->name), "load_group_from_stmt");
}

static int load_group_membership_from_stmt(sqlite3_stmt* stmt, int user_id,
                                           db_group_membership_t* out_item) {
  const unsigned char* group_name = NULL;
  const void* wrapped_group_key = NULL;
  int group_name_len = 0;
  int wrapped_group_key_len = 0;

  if (out_item == NULL) {
    return -1;
  }

  memset(out_item, 0, sizeof(*out_item));
  out_item->user_id = user_id;
  out_item->group_id = sqlite3_column_int(stmt, 0);
  out_item->group.id = out_item->group_id;

  group_name = sqlite3_column_text(stmt, 1);
  group_name_len = sqlite3_column_bytes(stmt, 1);
  wrapped_group_key = sqlite3_column_blob(stmt, 2);
  wrapped_group_key_len = sqlite3_column_bytes(stmt, 2);

  if (copy_text_value(group_name, group_name_len, out_item->group.name,
                      sizeof(out_item->group.name),
                      "load_group_membership_from_stmt") != 0 ||
      copy_blob_value(wrapped_group_key, wrapped_group_key_len,
                      out_item->wrapped_group_key,
                      sizeof(out_item->wrapped_group_key),
                      &out_item->wrapped_group_key_len,
                      "load_group_membership_from_stmt") != 0) {
    return -1;
  }

  return 0;
}

static int load_file_metadata_from_stmt(sqlite3_stmt* stmt,
                                        db_file_metadata_t* out_metadata) {
  const void* path = NULL;
  const void* name = NULL;
  const unsigned char* object_type = NULL;
  const void* wrapped_fek_owner = NULL;
  const void* wrapped_fek_group = NULL;
  const void* wrapped_fek_other = NULL;
  int path_len = 0;
  int name_len = 0;
  int object_type_len = 0;
  int wrapped_fek_owner_len = 0;
  int wrapped_fek_group_len = 0;
  int wrapped_fek_other_len = 0;

  if (out_metadata == NULL) {
    return -1;
  }

  memset(out_metadata, 0, sizeof(*out_metadata));
  out_metadata->id = sqlite3_column_int(stmt, 0);

  path = sqlite3_column_blob(stmt, 1);
  path_len = sqlite3_column_bytes(stmt, 1);
  name = sqlite3_column_blob(stmt, 2);
  name_len = sqlite3_column_bytes(stmt, 2);
  out_metadata->owner_id = sqlite3_column_int(stmt, 3);
  out_metadata->has_group_id = sqlite3_column_type(stmt, 4) != SQLITE_NULL;
  if (out_metadata->has_group_id) {
    out_metadata->group_id = sqlite3_column_int(stmt, 4);
  }
  out_metadata->mode_bits = sqlite3_column_int(stmt, 5);
  object_type = sqlite3_column_text(stmt, 6);
  object_type_len = sqlite3_column_bytes(stmt, 6);
  out_metadata->has_wrapped_fek_owner =
      sqlite3_column_type(stmt, 7) != SQLITE_NULL;
  wrapped_fek_owner = sqlite3_column_blob(stmt, 7);
  wrapped_fek_owner_len = sqlite3_column_bytes(stmt, 7);
  out_metadata->has_wrapped_fek_group =
      sqlite3_column_type(stmt, 8) != SQLITE_NULL;
  wrapped_fek_group = sqlite3_column_blob(stmt, 8);
  wrapped_fek_group_len = sqlite3_column_bytes(stmt, 8);
  out_metadata->has_wrapped_fek_other =
      sqlite3_column_type(stmt, 9) != SQLITE_NULL;
  wrapped_fek_other = sqlite3_column_blob(stmt, 9);
  wrapped_fek_other_len = sqlite3_column_bytes(stmt, 9);
  out_metadata->created_at = sqlite3_column_int64(stmt, 10);
  out_metadata->updated_at = sqlite3_column_int64(stmt, 11);

  if (copy_blob_value(path, path_len, out_metadata->path,
                      sizeof(out_metadata->path), &out_metadata->path_len,
                      "load_file_metadata_from_stmt") != 0 ||
      copy_blob_value(name, name_len, out_metadata->name,
                      sizeof(out_metadata->name), &out_metadata->name_len,
                      "load_file_metadata_from_stmt") != 0 ||
      copy_text_value(object_type, object_type_len, out_metadata->object_type,
                      sizeof(out_metadata->object_type),
                      "load_file_metadata_from_stmt") != 0) {
    return -1;
  }

  if (out_metadata->has_wrapped_fek_owner &&
      copy_blob_value(wrapped_fek_owner, wrapped_fek_owner_len,
                      out_metadata->wrapped_fek_owner,
                      sizeof(out_metadata->wrapped_fek_owner),
                      &out_metadata->wrapped_fek_owner_len,
                      "load_file_metadata_from_stmt") != 0) {
    return -1;
  }

  if (out_metadata->has_wrapped_fek_group &&
      copy_blob_value(wrapped_fek_group, wrapped_fek_group_len,
                      out_metadata->wrapped_fek_group,
                      sizeof(out_metadata->wrapped_fek_group),
                      &out_metadata->wrapped_fek_group_len,
                      "load_file_metadata_from_stmt") != 0) {
    return -1;
  }

  if (out_metadata->has_wrapped_fek_other &&
      copy_blob_value(wrapped_fek_other, wrapped_fek_other_len,
                      out_metadata->wrapped_fek_other,
                      sizeof(out_metadata->wrapped_fek_other),
                      &out_metadata->wrapped_fek_other_len,
                      "load_file_metadata_from_stmt") != 0) {
    return -1;
  }

  return 0;
}

static int is_direct_child_path(const unsigned char* parent, size_t parent_len,
                                const unsigned char* child, size_t child_len) {
  size_t i = 0;

  if (parent == NULL || child == NULL) {
    return 0;
  }

  if (parent_len == 1 && parent[0] == '/') {
    if (child_len <= 1 || child[0] != '/') {
      return 0;
    }

    for (i = 1; i < child_len; i++) {
      if (child[i] == '/') {
        return 0;
      }
    }
    return 1;
  }

  if (child_len <= parent_len + 1 || memcmp(parent, child, parent_len) != 0 ||
      child[parent_len] != '/') {
    return 0;
  }

  for (i = parent_len + 1; i < child_len; i++) {
    if (child[i] == '/') {
      return 0;
    }
  }

  return 1;
}

int db_init(server_context_t* ctx) {
  if (ctx == NULL) {
    return -1;
  }

  if (ctx->db_path == NULL || ctx->schema_path == NULL) {
    fprintf(stderr, "db_init: missing db path or schema path\n");
    return -1;
  }

  if (sqlite3_open(ctx->db_path, &ctx->db) != SQLITE_OK) {
    fprintf(stderr, "db_init: failed to open sqlite database at %s: %s\n",
            ctx->db_path, sqlite3_errmsg(ctx->db));
    db_cleanup(ctx);
    return -1;
  }

  if (exec_sql_statement(ctx->db, "PRAGMA foreign_keys = ON;",
                         "db_init: failed to enable foreign keys") != 0) {
    db_cleanup(ctx);
    return -1;
  }

  if (run_schema(ctx->db, ctx->schema_path) != 0) {
    fprintf(stderr, "db_init: failed to apply schema from %s\n",
            ctx->schema_path);
    db_cleanup(ctx);
    return -1;
  }

  fprintf(stderr, "db_init: opened %s and applied schema %s\n", ctx->db_path,
          ctx->schema_path);
  return 0;
}

void db_cleanup(server_context_t* ctx) {
  if (ctx == NULL || ctx->db == NULL) {
    return;
  }

  sqlite3_close(ctx->db);
  ctx->db = NULL;
}

sqlite3* db_handle(server_context_t* ctx) {
  if (ctx == NULL) {
    return NULL;
  }

  return ctx->db;
}

int db_find_user_by_username(server_context_t* ctx, const char* username,
                             db_user_t* out_user) {
  static const char sql[] =
      "SELECT id, username, password_hash, public_key "
      "FROM users WHERE username = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || username == NULL || out_user == NULL) {
    return -1;
  }

  memset(out_user, 0, sizeof(*out_user));
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_text_value(db, stmt, 1, username,
                      "db_find_user_by_username") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW || load_user_from_stmt(stmt, out_user) != 0) {
    fprintf(stderr, "db_find_user_by_username: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 1);
}

int db_find_user_by_id(server_context_t* ctx, int user_id,
                       db_user_t* out_user) {
  static const char sql[] =
      "SELECT id, username, password_hash, public_key "
      "FROM users WHERE id = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || out_user == NULL) {
    return -1;
  }

  memset(out_user, 0, sizeof(*out_user));
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_int_value(db, stmt, 1, user_id, "db_find_user_by_id") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW || load_user_from_stmt(stmt, out_user) != 0) {
    fprintf(stderr, "db_find_user_by_id: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 1);
}

int db_create_user(server_context_t* ctx, const char* username,
                   const char* password_hash, const void* public_key,
                   size_t public_key_len, int* out_user_id) {
  static const char sql[] =
      "INSERT INTO users (username, password_hash, public_key) "
      "VALUES (?1, ?2, ?3);";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || username == NULL || password_hash == NULL ||
      public_key == NULL) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_text_value(db, stmt, 1, username, "db_create_user") != 0 ||
      bind_text_value(db, stmt, 2, password_hash, "db_create_user") != 0 ||
      bind_blob_value(db, stmt, 3, public_key, public_key_len,
                      "db_create_user") != 0) {
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_create_user: insert failed: %s\n", sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_user_id != NULL) {
    *out_user_id = (int)sqlite3_last_insert_rowid(db);
  }

  return finish_statement(stmt, 0);
}

int db_find_group_by_name(server_context_t* ctx, const char* group_name,
                          db_group_t* out_group) {
  static const char sql[] = "SELECT id, name FROM groups WHERE name = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || group_name == NULL || out_group == NULL) {
    return -1;
  }

  memset(out_group, 0, sizeof(*out_group));
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_text_value(db, stmt, 1, group_name,
                      "db_find_group_by_name") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW || load_group_from_stmt(stmt, out_group) != 0) {
    fprintf(stderr, "db_find_group_by_name: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 1);
}

int db_find_group_by_id(server_context_t* ctx, int group_id,
                        db_group_t* out_group) {
  static const char sql[] = "SELECT id, name FROM groups WHERE id = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || out_group == NULL) {
    return -1;
  }

  memset(out_group, 0, sizeof(*out_group));
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_int_value(db, stmt, 1, group_id, "db_find_group_by_id") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW || load_group_from_stmt(stmt, out_group) != 0) {
    fprintf(stderr, "db_find_group_by_id: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 1);
}

int db_create_group(server_context_t* ctx, const char* group_name,
                    int* out_group_id) {
  static const char sql[] = "INSERT INTO groups (name) VALUES (?1);";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || group_name == NULL) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_text_value(db, stmt, 1, group_name, "db_create_group") != 0) {
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_create_group: insert failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_group_id != NULL) {
    *out_group_id = (int)sqlite3_last_insert_rowid(db);
  }

  return finish_statement(stmt, 0);
}

int db_add_user_to_group(server_context_t* ctx, int user_id, int group_id,
                         const void* wrapped_group_key,
                         size_t wrapped_group_key_len) {
  static const char sql[] =
      "INSERT INTO group_members (group_id, user_id, wrapped_group_key) "
      "VALUES (?1, ?2, ?3);";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || wrapped_group_key == NULL) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_int_value(db, stmt, 1, group_id, "db_add_user_to_group") != 0 ||
      bind_int_value(db, stmt, 2, user_id, "db_add_user_to_group") != 0 ||
      bind_blob_value(db, stmt, 3, wrapped_group_key, wrapped_group_key_len,
                      "db_add_user_to_group") != 0) {
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_add_user_to_group: insert failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 0);
}

int db_is_user_in_group(server_context_t* ctx, int user_id, int group_id,
                        int* out_is_member) {
  static const char sql[] =
      "SELECT 1 FROM group_members WHERE user_id = ?1 AND group_id = ?2;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || out_is_member == NULL) {
    return -1;
  }

  *out_is_member = 0;
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_int_value(db, stmt, 1, user_id, "db_is_user_in_group") != 0 ||
      bind_int_value(db, stmt, 2, group_id, "db_is_user_in_group") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW) {
    fprintf(stderr, "db_is_user_in_group: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  *out_is_member = 1;
  return finish_statement(stmt, 0);
}

int db_get_user_groups(server_context_t* ctx, int user_id,
                       db_group_membership_t* out_memberships,
                       size_t max_memberships, size_t* out_count) {
  static const char sql[] =
      "SELECT g.id, g.name, gm.wrapped_group_key "
      "FROM group_members gm "
      "JOIN groups g ON g.id = gm.group_id "
      "WHERE gm.user_id = ?1 "
      "ORDER BY g.name ASC, g.id ASC;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  size_t count = 0;
  int step_rc = SQLITE_ERROR;

  if (db == NULL || (out_memberships == NULL && max_memberships > 0)) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_int_value(db, stmt, 1, user_id, "db_get_user_groups") != 0) {
    return finish_statement(stmt, -1);
  }

  while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    if (out_memberships != NULL) {
      if (count >= max_memberships) {
        fprintf(stderr, "db_get_user_groups: output buffer too small\n");
        return finish_statement(stmt, -1);
      }
      if (load_group_membership_from_stmt(stmt, user_id,
                                          &out_memberships[count]) != 0) {
        return finish_statement(stmt, -1);
      }
    }
    count++;
  }

  if (step_rc != SQLITE_DONE) {
    fprintf(stderr, "db_get_user_groups: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_count != NULL) {
    *out_count = count;
  }

  return finish_statement(stmt, 0);
}

int db_create_file_metadata(server_context_t* ctx,
                            const db_file_metadata_t* metadata,
                            int* out_metadata_id) {
  static const char sql[] =
      "INSERT INTO file_metadatas ("
      "path, name, owner_id, group_id, mode_bits, object_type, "
      "wrapped_fek_owner, wrapped_fek_group, wrapped_fek_other, "
      "created_at, updated_at"
      ") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || metadata == NULL || metadata->object_type[0] == '\0') {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_blob_value(db, stmt, 1, metadata->path, metadata->path_len,
                      "db_create_file_metadata") != 0 ||
      bind_blob_value(db, stmt, 2, metadata->name, metadata->name_len,
                      "db_create_file_metadata") != 0 ||
      bind_int_value(db, stmt, 3, metadata->owner_id,
                     "db_create_file_metadata") != 0 ||
      bind_nullable_int_value(db, stmt, 4, metadata->has_group_id,
                              metadata->group_id,
                              "db_create_file_metadata") != 0 ||
      bind_int_value(db, stmt, 5, metadata->mode_bits,
                     "db_create_file_metadata") != 0 ||
      bind_text_value(db, stmt, 6, metadata->object_type,
                      "db_create_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 7, metadata->has_wrapped_fek_owner,
                               metadata->wrapped_fek_owner,
                               metadata->wrapped_fek_owner_len,
                               "db_create_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 8, metadata->has_wrapped_fek_group,
                               metadata->wrapped_fek_group,
                               metadata->wrapped_fek_group_len,
                               "db_create_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 9, metadata->has_wrapped_fek_other,
                               metadata->wrapped_fek_other,
                               metadata->wrapped_fek_other_len,
                               "db_create_file_metadata") != 0 ||
      sqlite3_bind_int64(stmt, 10, metadata->created_at) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 11, metadata->updated_at) != SQLITE_OK) {
    if (stmt != NULL && sqlite3_errcode(db) != SQLITE_OK) {
      fprintf(stderr, "db_create_file_metadata: bind failed: %s\n",
              sqlite3_errmsg(db));
    }
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_create_file_metadata: insert failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_metadata_id != NULL) {
    *out_metadata_id = (int)sqlite3_last_insert_rowid(db);
  }

  return finish_statement(stmt, 0);
}

int db_find_file_metadata_by_path(server_context_t* ctx, const void* path,
                                  size_t path_len,
                                  db_file_metadata_t* out_metadata) {
  static const char sql[] =
      "SELECT id, path, name, owner_id, group_id, mode_bits, object_type, "
      "wrapped_fek_owner, wrapped_fek_group, wrapped_fek_other, "
      "created_at, updated_at "
      "FROM file_metadatas WHERE path = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  int step_rc = SQLITE_ERROR;

  if (db == NULL || path == NULL || out_metadata == NULL) {
    return -1;
  }

  memset(out_metadata, 0, sizeof(*out_metadata));
  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_blob_value(db, stmt, 1, path, path_len,
                      "db_find_file_metadata_by_path") != 0) {
    return finish_statement(stmt, -1);
  }

  step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW ||
      load_file_metadata_from_stmt(stmt, out_metadata) != 0) {
    fprintf(stderr, "db_find_file_metadata_by_path: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, 1);
}

int db_list_children(server_context_t* ctx, const void* parent_path,
                     size_t parent_path_len, db_file_metadata_t* out_entries,
                     size_t max_entries, size_t* out_count) {
  static const char sql[] =
      "SELECT id, path, name, owner_id, group_id, mode_bits, object_type, "
      "wrapped_fek_owner, wrapped_fek_group, wrapped_fek_other, "
      "created_at, updated_at "
      "FROM file_metadatas "
      "ORDER BY CAST(name AS TEXT) ASC, id ASC;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);
  size_t count = 0;
  int step_rc = SQLITE_ERROR;

  if (db == NULL || parent_path == NULL ||
      (out_entries == NULL && max_entries > 0)) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0) {
    return finish_statement(stmt, -1);
  }

  while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    db_file_metadata_t metadata;
    if (load_file_metadata_from_stmt(stmt, &metadata) != 0) {
      return finish_statement(stmt, -1);
    }

    if (!is_direct_child_path(parent_path, parent_path_len, metadata.path,
                              metadata.path_len)) {
      continue;
    }

    if (out_entries != NULL) {
      if (count >= max_entries) {
        fprintf(stderr, "db_list_children: output buffer too small\n");
        return finish_statement(stmt, -1);
      }
      out_entries[count] = metadata;
    }
    count++;
  }

  if (step_rc != SQLITE_DONE) {
    fprintf(stderr, "db_list_children: query failed: %s\n", sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_count != NULL) {
    *out_count = count;
  }

  return finish_statement(stmt, 0);
}

int db_update_file_metadata(server_context_t* ctx, const void* current_path,
                            size_t current_path_len,
                            const db_file_metadata_t* metadata) {
  static const char sql[] =
      "UPDATE file_metadatas SET "
      "path = ?1, name = ?2, owner_id = ?3, group_id = ?4, mode_bits = ?5, "
      "object_type = ?6, wrapped_fek_owner = ?7, wrapped_fek_group = ?8, "
      "wrapped_fek_other = ?9, created_at = ?10, updated_at = ?11 "
      "WHERE path = ?12;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || current_path == NULL || metadata == NULL ||
      metadata->object_type[0] == '\0') {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_blob_value(db, stmt, 1, metadata->path, metadata->path_len,
                      "db_update_file_metadata") != 0 ||
      bind_blob_value(db, stmt, 2, metadata->name, metadata->name_len,
                      "db_update_file_metadata") != 0 ||
      bind_int_value(db, stmt, 3, metadata->owner_id,
                     "db_update_file_metadata") != 0 ||
      bind_nullable_int_value(db, stmt, 4, metadata->has_group_id,
                              metadata->group_id,
                              "db_update_file_metadata") != 0 ||
      bind_int_value(db, stmt, 5, metadata->mode_bits,
                     "db_update_file_metadata") != 0 ||
      bind_text_value(db, stmt, 6, metadata->object_type,
                      "db_update_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 7, metadata->has_wrapped_fek_owner,
                               metadata->wrapped_fek_owner,
                               metadata->wrapped_fek_owner_len,
                               "db_update_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 8, metadata->has_wrapped_fek_group,
                               metadata->wrapped_fek_group,
                               metadata->wrapped_fek_group_len,
                               "db_update_file_metadata") != 0 ||
      bind_nullable_blob_value(db, stmt, 9, metadata->has_wrapped_fek_other,
                               metadata->wrapped_fek_other,
                               metadata->wrapped_fek_other_len,
                               "db_update_file_metadata") != 0 ||
      sqlite3_bind_int64(stmt, 10, metadata->created_at) != SQLITE_OK ||
      sqlite3_bind_int64(stmt, 11, metadata->updated_at) != SQLITE_OK ||
      bind_blob_value(db, stmt, 12, current_path, current_path_len,
                      "db_update_file_metadata") != 0) {
    if (stmt != NULL && sqlite3_errcode(db) != SQLITE_OK) {
      fprintf(stderr, "db_update_file_metadata: bind failed: %s\n",
              sqlite3_errmsg(db));
    }
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_update_file_metadata: update failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, sqlite3_changes(db) > 0 ? 1 : 0);
}

int db_delete_file_metadata(server_context_t* ctx, const void* path,
                            size_t path_len) {
  static const char sql[] = "DELETE FROM file_metadatas WHERE path = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || path == NULL) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0 ||
      bind_blob_value(db, stmt, 1, path, path_len,
                      "db_delete_file_metadata") != 0) {
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_delete_file_metadata: delete failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  return finish_statement(stmt, sqlite3_changes(db) > 0 ? 1 : 0);
}

int db_begin_transaction(server_context_t* ctx) {
  sqlite3* db = db_handle(ctx);

  if (db == NULL) {
    return -1;
  }

  return exec_sql_statement(db, "BEGIN TRANSACTION;", "db_begin_transaction");
}

int db_commit(server_context_t* ctx) {
  sqlite3* db = db_handle(ctx);

  if (db == NULL) {
    return -1;
  }

  return exec_sql_statement(db, "COMMIT;", "db_commit");
}

int db_rollback(server_context_t* ctx) {
  sqlite3* db = db_handle(ctx);

  if (db == NULL) {
    return -1;
  }

  return exec_sql_statement(db, "ROLLBACK;", "db_rollback");
}
