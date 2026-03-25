#include "auth.h"

#include <ctype.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "db.h"

static void set_json_response(http_message_t* response, int status_code,
                              const char* reason, const char* json_body) {
  response->status_code = status_code;
  strncpy(response->reason, reason, sizeof(response->reason) - 1);
  response->reason[sizeof(response->reason) - 1] = '\0';
  strncpy(response->content_type, "application/json",
          sizeof(response->content_type) - 1);
  response->content_type[sizeof(response->content_type) - 1] = '\0';
  strncpy((char*)response->body, json_body, sizeof(response->body) - 1);
  response->body[sizeof(response->body) - 1] = '\0';
  response->body_len = strlen((char*)response->body);
  response->content_length = response->body_len;
}

static void set_json_auth_success_response(http_message_t* response,
                                           int status_code,
                                           const char* reason,
                                           const char* status,
                                           const char* token,
                                           long expires_in_seconds) {
  char json_body[HTTP_MAX_BODY_LEN];

  snprintf(json_body, sizeof(json_body),
           "{\"status\":\"%s\",\"token\":\"%s\",\"expires_in\":%ld}", status,
           token, expires_in_seconds);
  strncpy(response->auth_token, token, sizeof(response->auth_token) - 1);
  response->auth_token[sizeof(response->auth_token) - 1] = '\0';
  set_json_response(response, status_code, reason, json_body);
}

static int validate_json_auth_request(const http_message_t* request,
                                      http_message_t* response,
                                      const char* action_name) {
  char message[128];

  if (request->method != POST) {
    snprintf(message, sizeof(message), "{\"error\":\"%s requires POST\"}",
             action_name);
    set_json_response(response, 405, "Method Not Allowed", message);
    return -1;
  }

  if (strncmp(request->content_type, "application/json",
              strlen("application/json")) != 0) {
    snprintf(message, sizeof(message),
             "{\"error\":\"%s requires application/json\"}", action_name);
    set_json_response(response, 415, "Unsupported Media Type", message);
    return -1;
  }

  if (request->body_len == 0) {
    snprintf(message, sizeof(message),
             "{\"error\":\"missing %s request body\"}", action_name);
    set_json_response(response, 400, "Bad Request", message);
    return -1;
  }

  return 0;
}

static int parse_json_string_field(const char* json, const char* key, char* out,
                                   size_t out_size) {
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);

  const char* key_start = strstr(json, pattern);
  if (key_start == NULL) {
    return -1;
  }

  const char* colon = strchr(key_start + strlen(pattern), ':');
  if (colon == NULL) {
    return -1;
  }

  const char* value = colon + 1;
  while (*value != '\0' && isspace((unsigned char)*value)) {
    value++;
  }

  if (*value != '"' || out_size == 0) {
    return -1;
  }
  value++;

  size_t out_len = 0;
  while (*value != '\0' && *value != '"') {
    if (*value == '\\' && value[1] != '\0') {
      value++;
    }
    if (out_len + 1 >= out_size) {
      return -1;
    }
    out[out_len++] = *value++;
  }

  if (*value != '"') {
    return -1;
  }

  out[out_len] = '\0';
  return 0;
}

static int generate_session_token(char* out_token, size_t out_size) {
  unsigned char random_bytes[16];
  static const char hex[] = "0123456789abcdef";
  size_t i = 0;

  if (out_token == NULL || out_size < sizeof(random_bytes) * 2 + 1) {
    return -1;
  }

  if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
    return -1;
  }

  for (i = 0; i < sizeof(random_bytes); ++i) {
    out_token[i * 2] = hex[random_bytes[i] >> 4];
    out_token[i * 2 + 1] = hex[random_bytes[i] & 0x0f];
  }
  out_token[sizeof(random_bytes) * 2] = '\0';

  return 0;
}

static int auth_store_session(server_context_t* ctx, int user_id,
                              const char* username, char* out_token,
                              size_t out_token_size) {
  size_t i = 0;
  server_session_t* empty_slot = NULL;
  time_t now = time(NULL);

  if (ctx == NULL || username == NULL || out_token == NULL) {
    return -1;
  }
  if (now == (time_t)-1) {
    return -1;
  }

  for (i = 0; i < SERVER_MAX_SESSIONS; ++i) {
    if (ctx->sessions[i].in_use && ctx->sessions[i].expires_at <= now) {
      memset(&ctx->sessions[i], 0, sizeof(ctx->sessions[i]));
    }
    if (ctx->sessions[i].in_use &&
        strcmp(ctx->sessions[i].username, username) == 0) {
      if (generate_session_token(ctx->sessions[i].token,
                                 sizeof(ctx->sessions[i].token)) != 0) {
        return -1;
      }
      ctx->sessions[i].user_id = user_id;
      ctx->sessions[i].expires_at = now + ctx->session_ttl_seconds;
      strncpy(out_token, ctx->sessions[i].token, out_token_size - 1);
      out_token[out_token_size - 1] = '\0';
      return 0;
    }
    if (!ctx->sessions[i].in_use && empty_slot == NULL) {
      empty_slot = &ctx->sessions[i];
    }
  }

  if (empty_slot == NULL) {
    return -1;
  }

  memset(empty_slot, 0, sizeof(*empty_slot));
  empty_slot->in_use = 1;
  empty_slot->user_id = user_id;
  strncpy(empty_slot->username, username, sizeof(empty_slot->username) - 1);
  if (generate_session_token(empty_slot->token, sizeof(empty_slot->token)) !=
      0) {
    empty_slot->in_use = 0;
    return -1;
  }
  empty_slot->expires_at = now + ctx->session_ttl_seconds;

  strncpy(out_token, empty_slot->token, out_token_size - 1);
  out_token[out_token_size - 1] = '\0';
  return 0;
}

const server_session_t* auth_session_from_token(server_context_t* ctx,
                                                const char* token) {
  size_t i = 0;
  time_t now = time(NULL);

  if (ctx == NULL || token == NULL || token[0] == '\0') {
    return NULL;
  }
  if (now == (time_t)-1) {
    return NULL;
  }

  for (i = 0; i < SERVER_MAX_SESSIONS; ++i) {
    if (ctx->sessions[i].in_use && ctx->sessions[i].expires_at <= now) {
      memset(&ctx->sessions[i], 0, sizeof(ctx->sessions[i]));
      continue;
    }
    if (ctx->sessions[i].in_use &&
        strcmp(ctx->sessions[i].token, token) == 0) {
      return &ctx->sessions[i];
    }
  }

  return NULL;
}

int auth_handle_login(server_context_t* ctx, const http_message_t* request,
                      http_message_t* response) {
  char username[DB_USERNAME_MAX];
  char password[DB_PASSWORD_HASH_MAX];
  char token[SERVER_MAX_TOKEN_LEN];
  db_user_t user;
  int lookup_rc = 0;

  if (ctx == NULL || request == NULL || response == NULL) {
    return -1;
  }

  if (validate_json_auth_request(request, response, "login") != 0) {
    return 0;
  }

  if (parse_json_string_field((const char*)request->body, "username", username,
                              sizeof(username)) != 0 ||
      parse_json_string_field((const char*)request->body, "password", password,
                              sizeof(password)) != 0) {
    set_json_response(response, 400, "Bad Request",
                      "{\"error\":\"invalid login JSON body\"}");
    return 0;
  }

  lookup_rc = db_find_user_by_username(ctx, username, &user);
  if (lookup_rc < 0) {
    set_json_response(response, 500, "Internal Server Error",
                      "{\"error\":\"failed to query user database\"}");
    return 0;
  }
  if (lookup_rc == 0) {
    set_json_response(response, 401, "Unauthorized",
                      "{\"error\":\"invalid username or password\"}");
    return 0;
  }

  // Placeholder auth flow: compare directly to the stored password field.
  // Replace this with proper password hashing and constant-time verification.
  if (strcmp(user.password_hash, password) != 0) {
    set_json_response(response, 401, "Unauthorized",
                      "{\"error\":\"invalid username or password\"}");
    return 0;
  }

  if (auth_store_session(ctx, user.id, user.username, token, sizeof(token)) !=
      0) {
    set_json_response(response, 500, "Internal Server Error",
                      "{\"error\":\"failed to create session\"}");
    return 0;
  }

  set_json_auth_success_response(response, 200, "OK", "ok", token,
                                 ctx->session_ttl_seconds);
  return 0;
}

int auth_handle_register(server_context_t* ctx, const http_message_t* request,
                         http_message_t* response) {
  char username[DB_USERNAME_MAX];
  char password[DB_PASSWORD_HASH_MAX];
  char token[SERVER_MAX_TOKEN_LEN];
  db_user_t existing_user;
  static const unsigned char empty_public_key[] = "";
  int lookup_rc = 0;
  int user_id = 0;

  if (ctx == NULL || request == NULL || response == NULL) {
    return -1;
  }

  if (validate_json_auth_request(request, response, "register") != 0) {
    return 0;
  }

  if (parse_json_string_field((const char*)request->body, "username", username,
                              sizeof(username)) != 0 ||
      parse_json_string_field((const char*)request->body, "password", password,
                              sizeof(password)) != 0) {
    set_json_response(response, 400, "Bad Request",
                      "{\"error\":\"invalid register JSON body\"}");
    return 0;
  }

  lookup_rc = db_find_user_by_username(ctx, username, &existing_user);
  if (lookup_rc < 0) {
    set_json_response(response, 500, "Internal Server Error",
                      "{\"error\":\"failed to query user database\"}");
    return 0;
  }
  if (lookup_rc == 1) {
    set_json_response(response, 409, "Conflict",
                      "{\"error\":\"username already exists\"}");
    return 0;
  }

  // Placeholder registration flow: store the received password directly in the
  // password_hash column and an empty public key. Replace both once the client
  // sends a real public key and the server hashes passwords properly.
  if (db_create_user(ctx, username, password, empty_public_key, 0, &user_id) !=
      0) {
    set_json_response(response, 500, "Internal Server Error",
                      "{\"error\":\"failed to create user\"}");
    return 0;
  }

  if (auth_store_session(ctx, user_id, username, token, sizeof(token)) != 0) {
    set_json_response(response, 500, "Internal Server Error",
                      "{\"error\":\"failed to create session\"}");
    return 0;
  }

  set_json_auth_success_response(response, 201, "Created", "registered", token,
                                 ctx->session_ttl_seconds);
  return 0;
}

int auth_validate_token(server_context_t* ctx, const http_message_t* request) {
  return auth_session_from_token(ctx, request->auth_token) == NULL ? -1 : 0;
}
