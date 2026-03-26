#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  unsigned char sign_key[crypto_sign_PUBLICKEYBYTES];
  int rc = 1;

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

  printf("seeded user '%s' into %s\n", username, db_path);
  rc = 0;

cleanup:
  if (stmt) {
    sqlite3_finalize(stmt);
  }
  if (db) {
    sqlite3_close(db);
  }
  return rc;
}
