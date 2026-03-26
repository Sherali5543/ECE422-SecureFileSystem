#include "server_context.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int server_context_init(server_context_t* ctx) {
  const char* session_ttl_env = NULL;
  char* endptr = NULL;

  if (ctx == NULL) {
    return -1;
  }

  if (sodium_init() < 0) {
    return -1;
  }

  ctx->db_path = getenv("DB_PATH");
  ctx->schema_path = getenv("DB_SCHEMA");
  ctx->storage_root = getenv("STORAGE_ROOT");
  session_ttl_env = getenv("SESSION_TTL_SECONDS");
  ctx->db = NULL;
  memset(&ctx->pending_login, 0, sizeof(ctx->pending_login));
  memset(ctx->sessions, 0, sizeof(ctx->sessions));
  ctx->session_ttl_seconds = SERVER_DEFAULT_SESSION_TTL_SECONDS;

  if (ctx->db_path == NULL) {
    ctx->db_path = "server/deploy/storage/sqlite_data/sfs.db";
  }

  if (ctx->schema_path == NULL) {
    ctx->schema_path = "server/db/init/001-schema.sql";
  }

  if (ctx->storage_root == NULL) {
    ctx->storage_root = "server/deploy/storage/sfs_storage";
  }

  if (session_ttl_env != NULL) {
    long ttl = strtol(session_ttl_env, &endptr, 10);
    if (endptr != session_ttl_env && *endptr == '\0' && ttl > 0) {
      ctx->session_ttl_seconds = ttl;
    }
  }

  return 0;
}
