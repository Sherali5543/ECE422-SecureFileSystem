#include "db.h"

#include <stdio.h>
#include <string.h>

#include "schema_helper.h"

static int prepare_statement(sqlite3* db, sqlite3_stmt** stmt, const char* sql) {
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

  if (sqlite3_exec(ctx->db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL) !=
      SQLITE_OK) {
    fprintf(stderr, "db_init: failed to enable foreign keys: %s\n",
            sqlite3_errmsg(ctx->db));
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

  if (db == NULL || username == NULL || out_user == NULL) {
    return -1;
  }

  memset(out_user, 0, sizeof(*out_user));
  if (prepare_statement(db, &stmt, sql) != 0) {
    return -1;
  }

  if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    fprintf(stderr, "db_find_user_by_username: bind failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  int step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW) {
    fprintf(stderr, "db_find_user_by_username: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  out_user->id = sqlite3_column_int(stmt, 0);

  const unsigned char* db_username = sqlite3_column_text(stmt, 1);
  const unsigned char* db_password_hash = sqlite3_column_text(stmt, 2);
  const void* db_public_key = sqlite3_column_blob(stmt, 3);
  int db_public_key_len = sqlite3_column_bytes(stmt, 3);

  if (db_username == NULL || db_password_hash == NULL || db_public_key == NULL ||
      db_public_key_len < 0 ||
      (size_t)db_public_key_len > sizeof(out_user->public_key)) {
    fprintf(stderr, "db_find_user_by_username: invalid row contents\n");
    return finish_statement(stmt, -1);
  }

  strncpy(out_user->username, (const char*)db_username,
          sizeof(out_user->username) - 1);
  strncpy(out_user->password_hash, (const char*)db_password_hash,
          sizeof(out_user->password_hash) - 1);
  memcpy(out_user->public_key, db_public_key, (size_t)db_public_key_len);
  out_user->public_key_len = (size_t)db_public_key_len;

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

  if (prepare_statement(db, &stmt, sql) != 0) {
    return -1;
  }

  if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
      sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_TRANSIENT) !=
          SQLITE_OK) {
    fprintf(stderr, "db_create_user: bind failed: %s\n", sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if ((public_key_len == 0 &&
       sqlite3_bind_zeroblob(stmt, 3, 0) != SQLITE_OK) ||
      (public_key_len > 0 &&
       sqlite3_bind_blob(stmt, 3, public_key, (int)public_key_len,
                         SQLITE_TRANSIENT) != SQLITE_OK)) {
    fprintf(stderr, "db_create_user: public key bind failed: %s\n",
            sqlite3_errmsg(db));
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
  static const char sql[] =
      "SELECT id, name FROM groups WHERE name = ?1;";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || group_name == NULL || out_group == NULL) {
    return -1;
  }

  memset(out_group, 0, sizeof(*out_group));
  if (prepare_statement(db, &stmt, sql) != 0) {
    return -1;
  }

  if (sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_TRANSIENT) !=
      SQLITE_OK) {
    fprintf(stderr, "db_find_group_by_name: bind failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  int step_rc = sqlite3_step(stmt);
  if (step_rc == SQLITE_DONE) {
    return finish_statement(stmt, 0);
  }
  if (step_rc != SQLITE_ROW) {
    fprintf(stderr, "db_find_group_by_name: query failed: %s\n",
            sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  out_group->id = sqlite3_column_int(stmt, 0);
  const unsigned char* db_group_name = sqlite3_column_text(stmt, 1);
  if (db_group_name == NULL) {
    fprintf(stderr, "db_find_group_by_name: invalid row contents\n");
    return finish_statement(stmt, -1);
  }

  strncpy(out_group->name, (const char*)db_group_name,
          sizeof(out_group->name) - 1);
  return finish_statement(stmt, 1);
}

int db_create_group(server_context_t* ctx, const char* group_name,
                    int* out_group_id) {
  static const char sql[] =
      "INSERT INTO groups (name) VALUES (?1);";
  sqlite3_stmt* stmt = NULL;
  sqlite3* db = db_handle(ctx);

  if (db == NULL || group_name == NULL) {
    return -1;
  }

  if (prepare_statement(db, &stmt, sql) != 0) {
    return -1;
  }

  if (sqlite3_bind_text(stmt, 1, group_name, -1, SQLITE_TRANSIENT) !=
      SQLITE_OK) {
    fprintf(stderr, "db_create_group: bind failed: %s\n", sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_create_group: insert failed: %s\n", sqlite3_errmsg(db));
    return finish_statement(stmt, -1);
  }

  if (out_group_id != NULL) {
    *out_group_id = (int)sqlite3_last_insert_rowid(db);
  }

  return finish_statement(stmt, 0);
}
