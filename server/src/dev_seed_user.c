#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "db.h"

#define STORAGE_COMPONENT_HEX_MAX 512

static int encrypt_name_component_hex(const unsigned char* name_key,
                                      const char* component, char* out_hex,
                                      size_t out_hex_len) {
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char packed[crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES +
                       DB_FILE_NAME_MAX];
  unsigned char ciphertext[crypto_secretbox_MACBYTES + DB_FILE_NAME_MAX];
  size_t component_len = 0;
  size_t packed_len = 0;

  if (name_key == NULL || component == NULL || out_hex == NULL) {
    return -1;
  }

  component_len = strlen(component);
  if (component_len == 0 || component_len > DB_FILE_NAME_MAX) {
    return -1;
  }

  crypto_generichash(nonce, sizeof(nonce), (const unsigned char*)component,
                     (unsigned long long)component_len, name_key,
                     crypto_secretbox_KEYBYTES);
  crypto_secretbox_easy(ciphertext, (const unsigned char*)component,
                        (unsigned long long)component_len, nonce, name_key);

  packed_len = sizeof(nonce) + crypto_secretbox_MACBYTES + component_len;
  if (out_hex_len < packed_len * 2 + 1) {
    return -1;
  }

  memcpy(packed, nonce, sizeof(nonce));
  memcpy(packed + sizeof(nonce), ciphertext,
         crypto_secretbox_MACBYTES + component_len);
  sodium_bin2hex(out_hex, out_hex_len, packed, packed_len);
  sodium_memzero(nonce, sizeof(nonce));
  sodium_memzero(ciphertext, sizeof(ciphertext));
  sodium_memzero(packed, sizeof(packed));
  return 0;
}

static int seed_home_directories(sqlite3* db, int user_id, const char* username,
                                 const unsigned char* name_key) {
  sqlite3_stmt* stmt = NULL;
  char home_component[STORAGE_COMPONENT_HEX_MAX];
  char user_component[STORAGE_COMPONENT_HEX_MAX];
  char home_path[DB_FILE_PATH_MAX];
  char user_home_path[DB_FILE_PATH_MAX];
  long long now = (long long)time(NULL);
  int rc = -1;

  if (db == NULL || username == NULL || name_key == NULL || user_id <= 0) {
    return -1;
  }

  if (encrypt_name_component_hex(name_key, "home", home_component,
                                 sizeof(home_component)) != 0 ||
      encrypt_name_component_hex(name_key, username, user_component,
                                 sizeof(user_component)) != 0) {
    return -1;
  }

  if (snprintf(home_path, sizeof(home_path), "/%s", home_component) < 0 ||
      snprintf(user_home_path, sizeof(user_home_path), "/%s/%s", home_component,
               user_component) < 0) {
    return -1;
  }

  if (sqlite3_prepare_v2(
          db,
          "INSERT OR IGNORE INTO file_metadatas "
          "(path, name, owner_id, group_id, mode_bits, object_type, created_at, "
          "updated_at) VALUES (?1, ?2, ?3, NULL, ?4, 'directory', ?5, ?5);",
          -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to prepare directory insert: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_bind_blob(stmt, 1, home_path, strlen(home_path), SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 2, home_component, strlen(home_component),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  sqlite3_bind_int(stmt, 4, 0750);
  sqlite3_bind_int64(stmt, 5, now);
  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "failed to insert /home directory: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (sqlite3_prepare_v2(
          db,
          "INSERT OR IGNORE INTO file_metadatas "
          "(path, name, owner_id, group_id, mode_bits, object_type, created_at, "
          "updated_at) VALUES (?1, ?2, ?3, NULL, ?4, 'directory', ?5, ?5);",
          -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to prepare user home insert: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_bind_blob(stmt, 1, user_home_path, strlen(user_home_path),
                    SQLITE_TRANSIENT);
  sqlite3_bind_blob(stmt, 2, user_component, strlen(user_component),
                    SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  sqlite3_bind_int(stmt, 4, 0750);
  sqlite3_bind_int64(stmt, 5, now);
  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "failed to insert user home directory: %s\n",
            sqlite3_errmsg(db));
    goto cleanup;
  }

  rc = 0;

cleanup:
  if (stmt) {
    sqlite3_finalize(stmt);
  }
  return rc;
}

static int derive_box_public_key(const char* username, const char* password,
                                 unsigned char out[crypto_box_PUBLICKEYBYTES]) {
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_box_SECRETKEYBYTES];
  unsigned char seed[crypto_box_SEEDBYTES];
  size_t username_len = 0;
  size_t password_len = 0;

  if (!username || !password || !out) {
    return -1;
  }

  username_len = strlen(username);
  password_len = strlen(password);
  if (username_len + password_len + 2 > sizeof(seed)) {
    return -1;
  }

  memset(seed, 0, sizeof(seed));
  memcpy(seed, username, username_len);
  seed[username_len] = '.';
  memcpy(seed + username_len + 1, password, password_len);
  seed[username_len + password_len + 1] = '\0';

  crypto_box_seed_keypair(public_key, secret_key, seed);
  memcpy(out, public_key, crypto_box_PUBLICKEYBYTES);
  sodium_memzero(secret_key, sizeof(secret_key));
  sodium_memzero(seed, sizeof(seed));
  return 0;
}

static int derive_sign_public_key(const char* username, const char* password,
                                  unsigned char out[crypto_sign_PUBLICKEYBYTES]) {
  unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
  unsigned char seed[crypto_sign_SEEDBYTES];
  size_t username_len = 0;
  size_t password_len = 0;

  if (!username || !password || !out) {
    return -1;
  }

  username_len = strlen(username);
  password_len = strlen(password);
  if (username_len + password_len + 2 > sizeof(seed)) {
    return -1;
  }

  memset(seed, 0, sizeof(seed));
  memcpy(seed, username, username_len);
  seed[username_len] = '.';
  memcpy(seed + username_len + 1, password, password_len);
  seed[username_len + password_len + 1] = '\0';

  crypto_sign_seed_keypair(public_key, secret_key, seed);
  memcpy(out, public_key, crypto_sign_PUBLICKEYBYTES);
  sodium_memzero(secret_key, sizeof(secret_key));
  sodium_memzero(seed, sizeof(seed));
  return 0;
}

int main(int argc, char** argv) {
  sqlite3* db = NULL;
  sqlite3_stmt* stmt = NULL;
  const char* db_path = NULL;
  const char* username = NULL;
  const char* password = NULL;
  unsigned char enc_key[crypto_box_PUBLICKEYBYTES];
  unsigned char enc_secret_key[crypto_box_SECRETKEYBYTES];
  unsigned char sign_key[crypto_sign_PUBLICKEYBYTES];
  int rc = 1;
  int user_id = 0;

  if (argc != 4) {
    fprintf(stderr, "usage: %s <db_path> <username> <password>\n", argv[0]);
    return 1;
  }

  if (sodium_init() < 0) {
    fprintf(stderr, "failed to initialize libsodium\n");
    return 1;
  }

  db_path = argv[1];
  username = argv[2];
  password = argv[3];

  if (derive_box_public_key(username, password, enc_key) != 0 ||
      derive_sign_public_key(username, password, sign_key) != 0) {
    fprintf(stderr, "failed to derive public keys\n");
    return 1;
  }

  {
    unsigned char seed[crypto_box_SEEDBYTES];
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);

    memset(seed, 0, sizeof(seed));
    memcpy(seed, username, username_len);
    seed[username_len] = '.';
    memcpy(seed + username_len + 1, password, password_len);
    seed[username_len + password_len + 1] = '\0';
    crypto_box_seed_keypair(enc_key, enc_secret_key, seed);
    sodium_memzero(seed, sizeof(seed));
  }

  if (sqlite3_open(db_path, &db) != SQLITE_OK) {
    fprintf(stderr, "failed to open db: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }

  if (sqlite3_prepare_v2(
          db,
          "INSERT OR REPLACE INTO users "
          "(id, username, public_encryption_key, public_signing_key) "
          "VALUES ((SELECT id FROM users WHERE username = ?1), ?1, ?2, ?3);",
          -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to prepare statement: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, enc_key, sizeof(enc_key), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, sign_key, sizeof(sign_key), SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "failed to insert user: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (sqlite3_prepare_v2(db, "SELECT id FROM users WHERE username = ?1;", -1,
                         &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "failed to prepare id lookup: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  if (sqlite3_step(stmt) != SQLITE_ROW) {
    fprintf(stderr, "failed to fetch user id: %s\n", sqlite3_errmsg(db));
    goto cleanup;
  }
  user_id = sqlite3_column_int(stmt, 0);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (seed_home_directories(db, user_id, username, enc_secret_key) != 0) {
    goto cleanup;
  }

  printf("seeded user '%s' into %s\n", username, db_path);
  rc = 0;

cleanup:
  sodium_memzero(enc_secret_key, sizeof(enc_secret_key));
  if (stmt) {
    sqlite3_finalize(stmt);
  }
  if (db) {
    sqlite3_close(db);
  }
  return rc;
}
