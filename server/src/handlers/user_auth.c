#include "handlers.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cjson/cJSON.h"
#include "db.h"
#include "encryption.h"
#include "http.h"
#include "server_context.h"
#include "tls.h"

#define LOGIN_BODY_MAX 2048
#define SESSION_TOKEN_BYTES 32

typedef struct {
  char* body;
  cJSON* json;
  const char* username;
  const char* signature_hex;
} login_request_t;

typedef struct {
  char* body;
  cJSON* json;
  const char* username;
  const char* public_encryption_key_hex;
  const char* public_signing_key_hex;
  const char* home_path;
  const char* home_name;
  const char* user_home_path;
  const char* user_home_name;
} register_request_t;

static void set_json_response(http_message_t* response, int status,
                              const char* reason, size_t content_length) {
  response->status_code = status;
  strncpy(response->reason, reason, sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  response->content_type = JSON;
  response->content_length = content_length;
  strncpy(response->connection, "close", sizeof(response->connection) - 1);
  response->connection[sizeof(response->connection) - 1] = '\0';
}

static int write_json_body(SSL* ssl, const char* json) {
  size_t len = strlen(json);
  return (tls_write(ssl, (void*)json, len) == (ssize_t)len) ? 0 : -1;
}

static void send_json_error(SSL* ssl, http_message_t* response, int status,
                            const char* reason, const char* json_body) {
  set_json_response(response, status, reason, strlen(json_body));
  send_response(ssl, response);
  write_json_body(ssl, json_body);
}

static int read_exact_body(http_message_t* msg, SSL* ssl, char* buf,
                           size_t len) {
  if (read_message_body(ssl, msg, buf, len) != (ssize_t)len) {
    return -1;
  }

  buf[len] = '\0';
  return 0;
}

static void cleanup_login_request(login_request_t* req) {
  if (!req) {
    return;
  }
  if (req->json) {
    cJSON_Delete(req->json);
  }
  free(req->body);
  memset(req, 0, sizeof(*req));
}

static void cleanup_register_request(register_request_t* req) {
  if (!req) {
    return;
  }
  if (req->json) {
    cJSON_Delete(req->json);
  }
  free(req->body);
  memset(req, 0, sizeof(*req));
}

static int hex_digit_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_encode(const unsigned char* bytes, size_t len, char* out,
                      size_t out_len) {
  static const char hex_chars[] = "0123456789abcdef";

  if (!bytes || !out || out_len < len * 2 + 1) {
    return -1;
  }

  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex_chars[bytes[i] >> 4];
    out[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
  }
  out[len * 2] = '\0';
  return 0;
}

static int hex_decode(const char* hex, unsigned char* out, size_t out_len,
                      size_t* decoded_len) {
  size_t hex_len = 0;

  if (!hex || !out || !decoded_len) {
    return -1;
  }

  hex_len = strlen(hex);
  if ((hex_len % 2) != 0 || out_len < hex_len / 2) {
    return -1;
  }

  for (size_t i = 0; i < hex_len / 2; i++) {
    int hi = hex_digit_value(hex[i * 2]);
    int lo = hex_digit_value(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }

  *decoded_len = hex_len / 2;
  return 0;
}

static int parse_login_request(http_message_t* msg, SSL* ssl,
                               http_message_t* response, login_request_t* out) {
  cJSON* username_json = NULL;
  cJSON* signature_json = NULL;

  if (!msg || !ssl || !response || !out) {
    return -1;
  }

  memset(out, 0, sizeof(*out));

  if (msg->content_type != JSON) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 415, "Unsupported Media Type",
                    "{\"error\":\"expected application/json\"}");
    return -1;
  }

  if (msg->content_length == 0 || msg->content_length > LOGIN_BODY_MAX) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid login request body\"}");
    return -1;
  }

  out->body = malloc(msg->content_length + 1);
  if (!out->body) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to allocate login buffer\"}");
    return -1;
  }

  if (read_exact_body(msg, ssl, out->body, msg->content_length) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"failed to read login body\"}");
    return -1;
  }

  out->json = cJSON_Parse(out->body);
  if (!out->json) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid json body\"}");
    return -1;
  }

  username_json = cJSON_GetObjectItemCaseSensitive(out->json, "username");
  if (!cJSON_IsString(username_json) || username_json->valuestring == NULL ||
      username_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"username is required\"}");
    return -1;
  }

  signature_json = cJSON_GetObjectItemCaseSensitive(out->json, "signature");
  if (signature_json != NULL &&
      (!cJSON_IsString(signature_json) || signature_json->valuestring == NULL ||
       signature_json->valuestring[0] == '\0')) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"signature must be a non-empty string\"}");
    return -1;
  }

  out->username = username_json->valuestring;
  out->signature_hex =
      cJSON_IsString(signature_json) ? signature_json->valuestring : NULL;
  return 0;
}

static int parse_register_request(http_message_t* msg, SSL* ssl,
                                  http_message_t* response,
                                  register_request_t* out) {
  cJSON* username_json = NULL;
  cJSON* enc_key_json = NULL;
  cJSON* sign_key_json = NULL;
  cJSON* home_path_json = NULL;
  cJSON* home_name_json = NULL;
  cJSON* user_home_path_json = NULL;
  cJSON* user_home_name_json = NULL;

  if (!msg || !ssl || !response || !out) {
    return -1;
  }

  memset(out, 0, sizeof(*out));

  if (msg->content_type != JSON) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 415, "Unsupported Media Type",
                    "{\"error\":\"expected application/json\"}");
    return -1;
  }

  if (msg->content_length == 0 || msg->content_length > LOGIN_BODY_MAX) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid registration request body\"}");
    return -1;
  }

  out->body = malloc(msg->content_length + 1);
  if (!out->body) {
    drain_message_body(ssl, msg, msg->content_length);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to allocate registration buffer\"}");
    return -1;
  }

  if (read_exact_body(msg, ssl, out->body, msg->content_length) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"failed to read registration body\"}");
    return -1;
  }

  out->json = cJSON_Parse(out->body);
  if (!out->json) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid json body\"}");
    return -1;
  }

  username_json = cJSON_GetObjectItemCaseSensitive(out->json, "username");
  enc_key_json =
      cJSON_GetObjectItemCaseSensitive(out->json, "public_encryption_key");
  sign_key_json =
      cJSON_GetObjectItemCaseSensitive(out->json, "public_signing_key");
  home_path_json = cJSON_GetObjectItemCaseSensitive(out->json, "home_path");
  home_name_json = cJSON_GetObjectItemCaseSensitive(out->json, "home_name");
  user_home_path_json =
      cJSON_GetObjectItemCaseSensitive(out->json, "user_home_path");
  user_home_name_json =
      cJSON_GetObjectItemCaseSensitive(out->json, "user_home_name");

  if (!cJSON_IsString(username_json) || username_json->valuestring == NULL ||
      username_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"username is required\"}");
    return -1;
  }
  if (!cJSON_IsString(enc_key_json) || enc_key_json->valuestring == NULL ||
      enc_key_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"public_encryption_key is required\"}");
    return -1;
  }
  if (!cJSON_IsString(sign_key_json) || sign_key_json->valuestring == NULL ||
      sign_key_json->valuestring[0] == '\0') {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"public_signing_key is required\"}");
    return -1;
  }
  if ((home_path_json != NULL &&
       (!cJSON_IsString(home_path_json) || home_path_json->valuestring == NULL ||
        home_path_json->valuestring[0] == '\0')) ||
      (home_name_json != NULL &&
       (!cJSON_IsString(home_name_json) || home_name_json->valuestring == NULL ||
        home_name_json->valuestring[0] == '\0')) ||
      (user_home_path_json != NULL &&
       (!cJSON_IsString(user_home_path_json) ||
        user_home_path_json->valuestring == NULL ||
        user_home_path_json->valuestring[0] == '\0')) ||
      (user_home_name_json != NULL &&
       (!cJSON_IsString(user_home_name_json) ||
        user_home_name_json->valuestring == NULL ||
        user_home_name_json->valuestring[0] == '\0'))) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid encrypted home metadata\"}");
    return -1;
  }

  out->username = username_json->valuestring;
  out->public_encryption_key_hex = enc_key_json->valuestring;
  out->public_signing_key_hex = sign_key_json->valuestring;
  out->home_path =
      cJSON_IsString(home_path_json) ? home_path_json->valuestring : NULL;
  out->home_name =
      cJSON_IsString(home_name_json) ? home_name_json->valuestring : NULL;
  out->user_home_path = cJSON_IsString(user_home_path_json)
                            ? user_home_path_json->valuestring
                            : NULL;
  out->user_home_name = cJSON_IsString(user_home_name_json)
                            ? user_home_name_json->valuestring
                            : NULL;
  return 0;
}

static int create_registration_home_directories(server_context_t* ctx,
                                                const register_request_t* req,
                                                int user_id) {
  db_file_metadata_t home_meta;
  db_file_metadata_t user_home_meta;
  int ignored_id = 0;
  long long now = (long long)time(NULL);

  if (ctx == NULL || req == NULL) {
    return -1;
  }
  if (req->home_path == NULL || req->home_name == NULL ||
      req->user_home_path == NULL || req->user_home_name == NULL) {
    return 0;
  }

  memset(&home_meta, 0, sizeof(home_meta));
  memcpy(home_meta.path, req->home_path, strlen(req->home_path));
  home_meta.path_len = strlen(req->home_path);
  memcpy(home_meta.name, req->home_name, strlen(req->home_name));
  home_meta.name_len = strlen(req->home_name);
  home_meta.owner_id = user_id;
  home_meta.mode_bits = 0750;
  strncpy(home_meta.object_type, "directory", sizeof(home_meta.object_type) - 1);
  home_meta.created_at = now;
  home_meta.updated_at = now;

  memset(&user_home_meta, 0, sizeof(user_home_meta));
  memcpy(user_home_meta.path, req->user_home_path, strlen(req->user_home_path));
  user_home_meta.path_len = strlen(req->user_home_path);
  memcpy(user_home_meta.name, req->user_home_name, strlen(req->user_home_name));
  user_home_meta.name_len = strlen(req->user_home_name);
  user_home_meta.owner_id = user_id;
  user_home_meta.mode_bits = 0750;
  strncpy(user_home_meta.object_type, "directory",
          sizeof(user_home_meta.object_type) - 1);
  user_home_meta.created_at = now;
  user_home_meta.updated_at = now;

  if (db_create_file_metadata(ctx, &home_meta, &ignored_id) != 0 &&
      db_find_file_metadata_by_path(ctx, req->home_path, strlen(req->home_path),
                                    &home_meta) < 0) {
    return -1;
  }
  if (db_create_file_metadata(ctx, &user_home_meta, &ignored_id) != 0 &&
      db_find_file_metadata_by_path(ctx, req->user_home_path,
                                    strlen(req->user_home_path),
                                    &user_home_meta) < 0) {
    return -1;
  }

  return 0;
}

static int parse_username_query(const http_message_t* msg, char* out_username,
                                size_t out_size) {
  static const char prefix[] = "username=";
  const char* value = NULL;
  size_t len = 0;

  if (!msg || !out_username || out_size == 0) {
    return -1;
  }
  if (strncmp(msg->query, prefix, sizeof(prefix) - 1) != 0) {
    return -1;
  }

  value = msg->query + sizeof(prefix) - 1;
  if (*value == '\0' || strchr(value, '&') != NULL) {
    return -1;
  }

  len = strlen(value);
  if (len >= out_size) {
    return -1;
  }

  memcpy(out_username, value, len);
  out_username[len] = '\0';
  return 0;
}

static void clear_pending_login(server_context_t* ctx) {
  if (!ctx) {
    return;
  }
  memset(&ctx->pending_login, 0, sizeof(ctx->pending_login));
}

static int issue_challenge(server_context_t* ctx, const db_user_t* user,
                           http_message_t* response, SSL* ssl) {
  char challenge_hex[SERVER_LOGIN_CHALLENGE_BYTES * 2 + 1];
  char json[256];
  int written = 0;

  if (!ctx || !user || !response || !ssl) {
    return -1;
  }

  clear_pending_login(ctx);
  ctx->pending_login.active = 1;
  ctx->pending_login.user_id = user->id;
  ctx->pending_login.challenge_len = SERVER_LOGIN_CHALLENGE_BYTES;
  strncpy(ctx->pending_login.username, user->username,
          sizeof(ctx->pending_login.username) - 1);
  ctx->pending_login.username[sizeof(ctx->pending_login.username) - 1] = '\0';
  populate_cryptorandom((char*)ctx->pending_login.challenge,
                        ctx->pending_login.challenge_len);

  if (hex_encode(ctx->pending_login.challenge, ctx->pending_login.challenge_len,
                 challenge_hex, sizeof(challenge_hex)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to encode challenge\"}");
    return -1;
  }

  written = snprintf(json, sizeof(json), "{\"challenge\":\"%s\"}",
                     challenge_hex);
  if (written < 0 || (size_t)written >= sizeof(json)) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build challenge response\"}");
    return -1;
  }

  set_json_response(response, 200, "OK", (size_t)written);
  send_response(ssl, response);
  write_json_body(ssl, json);
  return 0;
}

static int issue_session_token(server_context_t* ctx, const db_user_t* user,
                               char* token_out, size_t token_out_len) {
  unsigned char raw_token[SESSION_TOKEN_BYTES];

  if (!ctx || !user || !token_out) {
    return -1;
  }

  memset(ctx->sessions, 0, sizeof(ctx->sessions));
  populate_cryptorandom((char*)raw_token, sizeof(raw_token));
  if (hex_encode(raw_token, sizeof(raw_token), token_out, token_out_len) != 0) {
    return -1;
  }

  ctx->sessions[0].in_use = 1;
  ctx->sessions[0].user_id = user->id;
  strncpy(ctx->sessions[0].username, user->username,
          sizeof(ctx->sessions[0].username) - 1);
  ctx->sessions[0].username[sizeof(ctx->sessions[0].username) - 1] = '\0';
  strncpy(ctx->sessions[0].token, token_out, sizeof(ctx->sessions[0].token) - 1);
  ctx->sessions[0].token[sizeof(ctx->sessions[0].token) - 1] = '\0';
  ctx->sessions[0].expires_at = time(NULL) + ctx->session_ttl_seconds;
  return 0;
}

static int verify_signature_and_login(server_context_t* ctx,
                                      const login_request_t* req,
                                      const db_user_t* user,
                                      http_message_t* response, SSL* ssl) {
  unsigned char signed_challenge[crypto_sign_BYTES + SERVER_LOGIN_CHALLENGE_BYTES];
  unsigned char opened_message[SERVER_LOGIN_CHALLENGE_BYTES];
  unsigned long long opened_len = 0;
  size_t signed_len = 0;
  char token[SESSION_TOKEN_BYTES * 2 + 1];
  char json[256];
  int written = 0;

  if (!ctx || !req || !user || !response || !ssl) {
    return -1;
  }

  if (!ctx->pending_login.active) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"no pending login challenge\"}");
    return -1;
  }

  if (strncmp(ctx->pending_login.username, req->username,
              sizeof(ctx->pending_login.username)) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"pending challenge belongs to another user\"}");
    return -1;
  }

  if (user->id != ctx->pending_login.user_id) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid login state\"}");
    clear_pending_login(ctx);
    return -1;
  }

  if (hex_decode(req->signature_hex, signed_challenge, sizeof(signed_challenge),
                 &signed_len) != 0 ||
      signed_len != crypto_sign_BYTES + ctx->pending_login.challenge_len) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid signature encoding\"}");
    return -1;
  }

  if (crypto_sign_open(opened_message, &opened_len, signed_challenge, signed_len,
                       user->public_signing_key) != 0 ||
      opened_len != ctx->pending_login.challenge_len ||
      sodium_memcmp(opened_message, ctx->pending_login.challenge,
                    ctx->pending_login.challenge_len) != 0) {
    clear_pending_login(ctx);
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"signature verification failed\"}");
    return -1;
  }

  if (issue_session_token(ctx, user, token, sizeof(token)) != 0) {
    clear_pending_login(ctx);
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create session token\"}");
    return -1;
  }

  clear_pending_login(ctx);
  written = snprintf(json, sizeof(json), "{\"token\":\"%s\"}", token);
  if (written < 0 || (size_t)written >= sizeof(json)) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build token response\"}");
    return -1;
  }

  set_json_response(response, 200, "OK", (size_t)written);
  send_response(ssl, response);
  write_json_body(ssl, json);
  return 0;
}

void login_user(http_message_t* msg, SSL* ssl, http_message_t* response,
                server_context_t* ctx) {
  login_request_t req;
  db_user_t user;
  int user_found = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (parse_login_request(msg, ssl, response, &req) != 0) {
    cleanup_login_request(&req);
    return;
  }

  user_found = db_find_user_by_username(ctx, req.username, &user);
  if (user_found < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to query user\"}");
    cleanup_login_request(&req);
    return;
  }
  if (user_found == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"unknown user\"}");
    cleanup_login_request(&req);
    return;
  }

  if (req.signature_hex == NULL) {
    issue_challenge(ctx, &user, response, ssl);
  } else {
    verify_signature_and_login(ctx, &req, &user, response, ssl);
  }

  cleanup_login_request(&req);
}

void logout_user(http_message_t* msg, SSL* ssl, http_message_t* response,
                 server_context_t* ctx) {
  char json[] = "{\"message\":\"logged out\"}";

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->content_length > 0) {
    drain_message_body(ssl, msg, msg->content_length);
  }

  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }

  for (size_t i = 0; i < SERVER_MAX_SESSIONS; i++) {
    server_session_t* session = &ctx->sessions[i];

    if (!session->in_use) {
      continue;
    }
    if (strncmp(session->token, msg->auth_token, SERVER_MAX_TOKEN_LEN) != 0) {
      continue;
    }

    memset(session, 0, sizeof(*session));
    set_json_response(response, 200, "OK", strlen(json));
    send_response(ssl, response);
    write_json_body(ssl, json);
    return;
  }

  send_json_error(ssl, response, 401, "Unauthorized",
                  "{\"error\":\"invalid or expired token\"}");
}

void register_user(http_message_t* msg, SSL* ssl, http_message_t* response,
                   server_context_t* ctx) {
  register_request_t req;
  db_user_t existing_user;
  unsigned char public_encryption_key[DB_PUBLIC_ENCRYPTION_KEY_MAX];
  unsigned char public_signing_key[DB_PUBLIC_SIGNING_KEY_MAX];
  size_t public_encryption_key_len = 0;
  size_t public_signing_key_len = 0;
  int user_found = 0;
  int user_id = 0;
  char json[128];
  int written = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (parse_register_request(msg, ssl, response, &req) != 0) {
    cleanup_register_request(&req);
    return;
  }

  if (hex_decode(req.public_encryption_key_hex, public_encryption_key,
                 sizeof(public_encryption_key), &public_encryption_key_len) != 0 ||
      hex_decode(req.public_signing_key_hex, public_signing_key,
                 sizeof(public_signing_key), &public_signing_key_len) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid public key encoding\"}");
    cleanup_register_request(&req);
    return;
  }

  user_found = db_find_user_by_username(ctx, req.username, &existing_user);
  if (user_found < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to query existing user\"}");
    cleanup_register_request(&req);
    return;
  }
  if (user_found > 0) {
    send_json_error(ssl, response, 409, "Conflict",
                    "{\"error\":\"username already exists\"}");
    cleanup_register_request(&req);
    return;
  }

  if (db_create_user(ctx, req.username, public_encryption_key,
                     public_encryption_key_len, public_signing_key,
                     public_signing_key_len, &user_id) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create user\"}");
    cleanup_register_request(&req);
    return;
  }

  if (create_registration_home_directories(ctx, &req, user_id) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to create encrypted home directories\"}");
    cleanup_register_request(&req);
    return;
  }

  written = snprintf(json, sizeof(json),
                     "{\"message\":\"registered\",\"user_id\":%d}", user_id);
  if (written < 0 || (size_t)written >= sizeof(json)) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build registration response\"}");
    cleanup_register_request(&req);
    return;
  }

  set_json_response(response, 201, "Created", (size_t)written);
  send_response(ssl, response);
  write_json_body(ssl, json);
  cleanup_register_request(&req);
}

void get_user_keys(http_message_t* msg, SSL* ssl, http_message_t* response,
                   server_context_t* ctx) {
  db_user_t requester;
  db_user_t target;
  char username[DB_USERNAME_MAX];
  char public_encryption_key_hex[DB_PUBLIC_ENCRYPTION_KEY_MAX * 2 + 1];
  char public_signing_key_hex[DB_PUBLIC_SIGNING_KEY_MAX * 2 + 1];
  char json[4096];
  int written = 0;
  int rc = 0;

  if (!msg || !ssl || !response || !ctx) {
    return;
  }

  if (msg->auth_token[0] == '\0') {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"missing bearer token\"}");
    return;
  }

  requester.id = 0;
  for (size_t i = 0; i < SERVER_MAX_SESSIONS; i++) {
    server_session_t* session = &ctx->sessions[i];

    if (!session->in_use) {
      continue;
    }
    if (strncmp(session->token, msg->auth_token, SERVER_MAX_TOKEN_LEN) != 0) {
      continue;
    }
    requester.id = session->user_id;
    break;
  }

  if (requester.id == 0) {
    send_json_error(ssl, response, 401, "Unauthorized",
                    "{\"error\":\"invalid or expired token\"}");
    return;
  }

  if (parse_username_query(msg, username, sizeof(username)) != 0) {
    send_json_error(ssl, response, 400, "Bad Request",
                    "{\"error\":\"invalid username query\"}");
    return;
  }

  rc = db_find_user_by_username(ctx, username, &target);
  if (rc < 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to query user\"}");
    return;
  }
  if (rc == 0) {
    send_json_error(ssl, response, 404, "Not Found",
                    "{\"error\":\"unknown user\"}");
    return;
  }

  if (hex_encode(target.public_encryption_key, target.public_encryption_key_len,
                 public_encryption_key_hex,
                 sizeof(public_encryption_key_hex)) != 0 ||
      hex_encode(target.public_signing_key, target.public_signing_key_len,
                 public_signing_key_hex, sizeof(public_signing_key_hex)) != 0) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to encode user keys\"}");
    return;
  }

  written = snprintf(
      json, sizeof(json),
      "{\"username\":\"%s\",\"public_encryption_key\":\"%s\","
      "\"public_signing_key\":\"%s\"}",
      target.username, public_encryption_key_hex, public_signing_key_hex);
  if (written < 0 || (size_t)written >= sizeof(json)) {
    send_json_error(ssl, response, 500, "Internal Server Error",
                    "{\"error\":\"failed to build user key response\"}");
    return;
  }

  set_json_response(response, 200, "OK", (size_t)written);
  send_response(ssl, response);
  write_json_body(ssl, json);
}
