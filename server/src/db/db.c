#include "db.h"

#include <stdio.h>

#include "schema_helper.h"

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
