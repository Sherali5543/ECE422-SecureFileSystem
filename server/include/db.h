#ifndef SERVER_DB_H
#define SERVER_DB_H

#include <stddef.h>
#include <sqlite3.h>

#include "server_context.h"

#define DB_USERNAME_MAX 128
#define DB_PASSWORD_HASH_MAX 256
#define DB_PUBLIC_KEY_MAX 512
#define DB_GROUP_NAME_MAX 128

typedef struct {
  int id;
  char username[DB_USERNAME_MAX];
  char password_hash[DB_PASSWORD_HASH_MAX];
  unsigned char public_key[DB_PUBLIC_KEY_MAX];
  size_t public_key_len;
} db_user_t;

typedef struct {
  int id;
  char name[DB_GROUP_NAME_MAX];
} db_group_t;

int db_init(server_context_t* ctx);
void db_cleanup(server_context_t* ctx);
sqlite3* db_handle(server_context_t* ctx);
int db_find_user_by_username(server_context_t* ctx, const char* username,
                             db_user_t* out_user);
int db_create_user(server_context_t* ctx, const char* username,
                   const char* password_hash, const void* public_key,
                   size_t public_key_len, int* out_user_id);
int db_find_group_by_name(server_context_t* ctx, const char* group_name,
                          db_group_t* out_group);
int db_create_group(server_context_t* ctx, const char* group_name,
                    int* out_group_id);

#endif
