#ifndef SERVER_DB_H
#define SERVER_DB_H

#include <stddef.h>
#include <sqlite3.h>

#include "server_context.h"

#define DB_USERNAME_MAX 128
#define DB_PUBLIC_ENCRYPTION_KEY_MAX 512
#define DB_PUBLIC_SIGNING_KEY_MAX 512
#define DB_GROUP_NAME_MAX 128
#define DB_FILE_PATH_MAX 1024
#define DB_FILE_NAME_MAX 512
#define DB_WRAPPED_KEY_MAX 1024
#define DB_OBJECT_TYPE_MAX 16

typedef struct {
  int id;
  char username[DB_USERNAME_MAX];
  unsigned char public_encryption_key[DB_PUBLIC_ENCRYPTION_KEY_MAX];
  size_t public_encryption_key_len;
  unsigned char public_signing_key[DB_PUBLIC_SIGNING_KEY_MAX];
  size_t public_signing_key_len;
} db_user_t;

typedef struct {
  int id;
  char name[DB_GROUP_NAME_MAX];
} db_group_t;

typedef struct {
  int user_id;
  int group_id;
  db_group_t group;
  unsigned char wrapped_group_key[DB_WRAPPED_KEY_MAX];
  size_t wrapped_group_key_len;
} db_group_membership_t;

typedef struct {
  int id;
  unsigned char path[DB_FILE_PATH_MAX];
  size_t path_len;
  unsigned char name[DB_FILE_NAME_MAX];
  size_t name_len;
  int owner_id;
  int group_id;
  int has_group_id;
  int mode_bits;
  char object_type[DB_OBJECT_TYPE_MAX];
  unsigned char wrapped_fek_owner[DB_WRAPPED_KEY_MAX];
  size_t wrapped_fek_owner_len;
  int has_wrapped_fek_owner;
  unsigned char wrapped_fek_group[DB_WRAPPED_KEY_MAX];
  size_t wrapped_fek_group_len;
  int has_wrapped_fek_group;
  unsigned char wrapped_fek_other[DB_WRAPPED_KEY_MAX];
  size_t wrapped_fek_other_len;
  int has_wrapped_fek_other;
  long long created_at;
  long long updated_at;
} db_file_metadata_t;

int db_init(server_context_t* ctx);
void db_cleanup(server_context_t* ctx);
sqlite3* db_handle(server_context_t* ctx);

int db_find_user_by_username(server_context_t* ctx, const char* username,
                             db_user_t* out_user);
int db_find_user_by_id(server_context_t* ctx, int user_id,
                       db_user_t* out_user);
int db_create_user(server_context_t* ctx, const char* username,
                   const void* public_encryption_key,
                   size_t public_encryption_key_len,
                   const void* public_signing_key,
                   size_t public_signing_key_len,
                   int* out_user_id);

int db_find_group_by_name(server_context_t* ctx, const char* group_name,
                          db_group_t* out_group);
int db_find_group_by_id(server_context_t* ctx, int group_id,
                        db_group_t* out_group);
int db_create_group(server_context_t* ctx, const char* group_name,
                    int* out_group_id);

int db_add_user_to_group(server_context_t* ctx, int user_id, int group_id,
                         const void* wrapped_group_key,
                         size_t wrapped_group_key_len);
int db_remove_user_from_group(server_context_t* ctx, int user_id, int group_id);
int db_is_user_in_group(server_context_t* ctx, int user_id, int group_id,
                        int* out_is_member);
int db_get_user_groups(server_context_t* ctx, int user_id,
                       db_group_membership_t* out_memberships,
                       size_t max_memberships, size_t* out_count);

int db_create_file_metadata(server_context_t* ctx,
                            const db_file_metadata_t* metadata,
                            int* out_metadata_id);
int db_find_file_metadata_by_path(server_context_t* ctx, const void* path,
                                  size_t path_len,
                                  db_file_metadata_t* out_metadata);
int db_list_children(server_context_t* ctx, const void* parent_path,
                     size_t parent_path_len, db_file_metadata_t* out_entries,
                     size_t max_entries, size_t* out_count);
int db_update_file_metadata(server_context_t* ctx, const void* current_path,
                            size_t current_path_len,
                            const db_file_metadata_t* metadata);
int db_delete_file_metadata(server_context_t* ctx, const void* path,
                            size_t path_len);

int db_begin_transaction(server_context_t* ctx);
int db_commit(server_context_t* ctx);
int db_rollback(server_context_t* ctx);

#endif
