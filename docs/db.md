# Database Wrapper Guide

## Overview

[`server/src/db/db.c`](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/src/db/db.c) is the server's SQLite wrapper layer. It hides the raw SQL used for users, groups, group membership, file metadata, and transactions behind C functions declared in [`server/include/db.h`](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/include/db.h).

Use this layer when server code needs to read or write metadata without talking to SQLite directly.

## What You Need

To use `db.c`, you need:

- a [`server_context_t`](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/include/server_context.h) with `db_path` and `schema_path` set
- the schema file at [`server/db/init/001-schema.sql`](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/db/init/001-schema.sql)
- SQLite linked in your build
- `#include "db.h"` in the C file using the wrappers

If you call [`server_context_init(...)`](/Users/andy/Desktop/ece422/ECE422-SecureFileSystem/server/src/server_context.c), it fills in default values for:

- `DB_PATH` -> `server/deploy/storage/sqlite_data/sfs.db`
- `DB_SCHEMA` -> `server/db/init/001-schema.sql`

## Basic Setup

```c
#include "db.h"
#include "server_context.h"

server_context_t ctx = {0};

ctx.db_path = "server/deploy/storage/sqlite_data/sfs.db";
ctx.schema_path = "server/db/init/001-schema.sql";

if (db_init(&ctx) != 0) {
  /* handle error */
}

/* use db_* functions here */

db_cleanup(&ctx);
```

Or, using the server defaults:

```c
server_context_t ctx = {0};

if (server_context_init(&ctx) != 0) {
  /* handle error */
}

if (db_init(&ctx) != 0) {
  /* handle error */
}

db_cleanup(&ctx);
```

## Return Values

Most wrappers follow one of these patterns:

- `-1` means error
- `0` means success but nothing was found or changed
- `1` means success and a row was found or changed

Creation-style functions usually return:

- `0` for success
- `-1` for error

Transaction helpers return:

- `0` for success
- `-1` for error

## Data Structures

### `db_user_t`

Represents a row from the `users` table, including `id`, `username`, `password_hash`, and the user's `public_key`.

### `db_group_t`

Represents a row from the `groups` table with a group `id` and `name`.

### `db_group_membership_t`

Represents a user's membership in a group, including the joined group info and the stored `wrapped_group_key`.

### `db_file_metadata_t`

Represents a row from `file_metadatas`, including path/name blobs, ownership, mode bits, object type, wrapped FEKs, and timestamps.

For optional DB fields, the wrapper uses flags such as:

- `has_group_id`
- `has_wrapped_fek_owner`
- `has_wrapped_fek_group`
- `has_wrapped_fek_other`

These flags must be set correctly before inserts or updates.

## Function Reference

### Connection and lifecycle

#### `int db_init(server_context_t* ctx);`

Opens the SQLite database from `ctx->db_path`, enables foreign keys, and applies the schema from `ctx->schema_path`.

#### `void db_cleanup(server_context_t* ctx);`

Closes the SQLite handle stored in the context and clears `ctx->db`.

#### `sqlite3* db_handle(server_context_t* ctx);`

Returns the raw SQLite handle from the context so callers can inspect it when needed.

### Users

#### `int db_find_user_by_username(server_context_t* ctx, const char* username, db_user_t* out_user);`

Looks up a user by username and fills `out_user` if a row exists.

#### `int db_find_user_by_id(server_context_t* ctx, int user_id, db_user_t* out_user);`

Looks up a user by numeric ID and fills `out_user` if a row exists.

#### `int db_create_user(server_context_t* ctx, const char* username, const char* password_hash, const void* public_key, size_t public_key_len, int* out_user_id);`

Inserts a new user row and optionally returns the inserted user ID.

### Groups

#### `int db_find_group_by_name(server_context_t* ctx, const char* group_name, db_group_t* out_group);`

Looks up a group by name and fills `out_group` if a row exists.

#### `int db_find_group_by_id(server_context_t* ctx, int group_id, db_group_t* out_group);`

Looks up a group by numeric ID and fills `out_group` if a row exists.

#### `int db_create_group(server_context_t* ctx, const char* group_name, int* out_group_id);`

Inserts a new group row and optionally returns the inserted group ID.

### Group membership

#### `int db_add_user_to_group(server_context_t* ctx, int user_id, int group_id, const void* wrapped_group_key, size_t wrapped_group_key_len);`

Adds a user to a group by inserting a row into `group_members` with the wrapped group key.

#### `int db_is_user_in_group(server_context_t* ctx, int user_id, int group_id, int* out_is_member);`

Checks whether a user is already a member of a given group.

#### `int db_get_user_groups(server_context_t* ctx, int user_id, db_group_membership_t* out_memberships, size_t max_memberships, size_t* out_count);`

Returns the groups a user belongs to and optionally copies each membership into the output buffer.

### File metadata

#### `int db_create_file_metadata(server_context_t* ctx, const db_file_metadata_t* metadata, int* out_metadata_id);`

Inserts a new `file_metadatas` row using the fields in `metadata`.

#### `int db_find_file_metadata_by_path(server_context_t* ctx, const void* path, size_t path_len, db_file_metadata_t* out_metadata);`

Looks up a metadata row by exact path blob and fills `out_metadata` if it exists.

#### `int db_list_children(server_context_t* ctx, const void* parent_path, size_t parent_path_len, db_file_metadata_t* out_entries, size_t max_entries, size_t* out_count);`

Returns the direct children of a parent path and optionally copies them into the output array.

#### `int db_update_file_metadata(server_context_t* ctx, const void* current_path, size_t current_path_len, const db_file_metadata_t* metadata);`

Updates the metadata row at `current_path` using the values from `metadata`.

#### `int db_delete_file_metadata(server_context_t* ctx, const void* path, size_t path_len);`

Deletes the metadata row for the exact path blob provided.

### Transactions

#### `int db_begin_transaction(server_context_t* ctx);`

Starts a SQLite transaction on the current database handle.

#### `int db_commit(server_context_t* ctx);`

Commits the active transaction so its writes become permanent.

#### `int db_rollback(server_context_t* ctx);`

Rolls back the active transaction and discards uncommitted writes.

## Notes and Gotchas

- `db_init()` must be called before any other wrapper that touches the database.
- `db_cleanup()` should always be called when the context is no longer using SQLite.
- File paths and names in `db_file_metadata_t` are stored as blobs, so both the byte buffer and its length matter.
- If an optional metadata field should be stored as `NULL`, its matching `has_*` flag must be set to `0`.
- Some expected failure cases, like duplicate inserts or foreign key violations, still print SQLite errors to `stderr`.
