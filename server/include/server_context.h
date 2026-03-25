#ifndef SERVER_CONTEXT_H
#define SERVER_CONTEXT_H

#include <sqlite3.h>
#include <time.h>

#define SERVER_MAX_SESSIONS 128
#define SERVER_MAX_USERNAME_LEN 128
#define SERVER_MAX_TOKEN_LEN 256
#define SERVER_DEFAULT_SESSION_TTL_SECONDS 3600

typedef struct {
  int in_use;
  int user_id;
  char username[SERVER_MAX_USERNAME_LEN];
  char token[SERVER_MAX_TOKEN_LEN];
  time_t expires_at;
} server_session_t;

typedef struct {
  const char* db_path;
  const char* schema_path;
  const char* storage_root;
  long session_ttl_seconds;
  sqlite3* db;
  server_session_t sessions[SERVER_MAX_SESSIONS];
} server_context_t;

int server_context_init(server_context_t* ctx);

#endif
