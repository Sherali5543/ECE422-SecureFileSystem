#include "session.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#include "encryption.h"
#include "cjson/cJSON.h"
#include "cli_utils.h"
#include "http.h"
#include "tls.h"

static int read_response_body(http_message_t* msg, SSL* ssl, char** out_body) {
  char* body = NULL;

  if (!msg || !ssl || !out_body) {
    return -1;
  }

  body = malloc(msg->content_length + 1);
  if (!body) {
    return -1;
  }

  if (read_message_body(ssl, msg, body, msg->content_length) !=
      (ssize_t)msg->content_length) {
    free(body);
    return -1;
  }

  body[msg->content_length] = '\0';
  *out_body = body;
  return 0;
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

static int send_login_json(SSL* ssl, const char* body) {
  http_message_t* msg = NULL;
  size_t body_len = 0;

  if (!ssl || !body) {
    return -1;
  }

  body_len = strlen(body);
  msg = init_request();
  if (!msg) {
    return -1;
  }

  msg->method = POST;
  strncpy(msg->path, "/auth/login", HTTP_MAX_PATH_LEN - 1);
  msg->path[HTTP_MAX_PATH_LEN - 1] = '\0';
  msg->content_type = JSON;
  msg->content_length = body_len;

  printf("client login request body: %s\n", body);
  send_request(ssl, msg);
  destroy_message(msg);

  return (tls_write(ssl, (void*)body, body_len) == (ssize_t)body_len) ? 0 : -1;
}

static int send_register_json(SSL* ssl, const char* body) {
  http_message_t* msg = NULL;
  size_t body_len = 0;

  if (!ssl || !body) {
    return -1;
  }

  body_len = strlen(body);
  msg = init_request();
  if (!msg) {
    return -1;
  }

  msg->method = POST;
  strncpy(msg->path, "/auth/register", HTTP_MAX_PATH_LEN - 1);
  msg->path[HTTP_MAX_PATH_LEN - 1] = '\0';
  msg->content_type = JSON;
  msg->content_length = body_len;

  printf("client register request body: %s\n", body);
  send_request(ssl, msg);
  destroy_message(msg);

  return (tls_write(ssl, (void*)body, body_len) == (ssize_t)body_len) ? 0 : -1;
}

static char* request_login_challenge(SSL* ssl, const char* username) {
  cJSON* json = NULL;
  cJSON* challenge_json = NULL;
  http_message_t* response = NULL;
  char* request_body = NULL;
  char* response_body = NULL;
  char* challenge = NULL;

  json = cJSON_CreateObject();
  if (!json) {
    return NULL;
  }

  cJSON_AddStringToObject(json, "username", username);
  request_body = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  if (!request_body) {
    return NULL;
  }

  if (send_login_json(ssl, request_body) != 0) {
    free(request_body);
    return NULL;
  }
  free(request_body);

  response = read_response(ssl);
  if (!response || response->status_code != 200 ||
      read_response_body(response, ssl, &response_body) != 0) {
    destroy_message(response);
    return NULL;
  }

  printf("client login response body: %s\n", response_body);

  json = cJSON_Parse(response_body);
  if (!json) {
    free(response_body);
    destroy_message(response);
    return NULL;
  }

  challenge_json = cJSON_GetObjectItemCaseSensitive(json, "challenge");
  if (cJSON_IsString(challenge_json) && challenge_json->valuestring != NULL) {
    challenge = strdup(challenge_json->valuestring);
  }

  cJSON_Delete(json);
  free(response_body);
  destroy_message(response);
  return challenge;
}

static char* submit_login_signature(SSL* ssl, const char* username,
                                    const char* signature_hex) {
  cJSON* json = NULL;
  cJSON* token_json = NULL;
  http_message_t* response = NULL;
  char* request_body = NULL;
  char* response_body = NULL;
  char* token = NULL;

  json = cJSON_CreateObject();
  if (!json) {
    return NULL;
  }

  cJSON_AddStringToObject(json, "username", username);
  cJSON_AddStringToObject(json, "signature", signature_hex);
  request_body = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  if (!request_body) {
    return NULL;
  }

  if (send_login_json(ssl, request_body) != 0) {
    free(request_body);
    return NULL;
  }
  free(request_body);

  response = read_response(ssl);
  if (!response || response->status_code != 200 ||
      read_response_body(response, ssl, &response_body) != 0) {
    destroy_message(response);
    return NULL;
  }

  printf("client login response body: %s\n", response_body);

  json = cJSON_Parse(response_body);
  if (!json) {
    free(response_body);
    destroy_message(response);
    return NULL;
  }

  token_json = cJSON_GetObjectItemCaseSensitive(json, "token");
  if (cJSON_IsString(token_json) && token_json->valuestring != NULL) {
    token = strdup(token_json->valuestring);
  }

  cJSON_Delete(json);
  free(response_body);
  destroy_message(response);
  return token;
}

int register_account(SSL* ssl) {
  UserKeys* user_keys = NULL;
  SignKeys* sign_keys = NULL;
  cJSON* json = NULL;
  http_message_t* response = NULL;
  char* username = NULL;
  char* pwd = NULL;
  char* request_body = NULL;
  char* response_body = NULL;
  char* home_component = NULL;
  char* user_home_component = NULL;
  char public_encryption_key_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
  char public_signing_key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
  unsigned char private_name_key[crypto_secretbox_KEYBYTES];
  char home_path[SESSION_PATH_MAX];
  char user_home_path[SESSION_PATH_MAX];
  int rc = -1;

  printf("New username: ");
  setStdinEcho(true);
  username = get_input();

  printf("New password: ");
  setStdinEcho(false);
  pwd = get_input();
  setStdinEcho(true);

  if (!username || !pwd) {
    goto cleanup;
  }

  user_keys = generate_read_keypair(username, pwd);
  sign_keys = generate_signing_keypair(username, pwd);
  if (!user_keys || !sign_keys) {
    fprintf(stderr, "Failed to derive registration keys\n");
    goto cleanup;
  }

  if (hex_encode(user_keys->public_key, crypto_box_PUBLICKEYBYTES,
                 public_encryption_key_hex,
                 sizeof(public_encryption_key_hex)) != 0 ||
      hex_encode(sign_keys->public_key, crypto_sign_PUBLICKEYBYTES,
                 public_signing_key_hex,
                 sizeof(public_signing_key_hex)) != 0) {
    fprintf(stderr, "Failed to encode registration keys\n");
    goto cleanup;
  }
  if (derive_private_name_key(user_keys, private_name_key) != 0) {
    fprintf(stderr, "Failed to derive private name key\n");
    goto cleanup;
  }
  home_component = encrypt_name_component_hex(private_name_key, "home");
  user_home_component =
      encrypt_name_component_hex(private_name_key, username);
  if (home_component == NULL || user_home_component == NULL ||
      snprintf(home_path, sizeof(home_path), "/%s", home_component) < 0 ||
      snprintf(user_home_path, sizeof(user_home_path), "/%s/%s", home_component,
               user_home_component) < 0) {
    fprintf(stderr, "Failed to encode encrypted home paths\n");
    goto cleanup;
  }

  json = cJSON_CreateObject();
  if (!json) {
    goto cleanup;
  }

  cJSON_AddStringToObject(json, "username", username);
  cJSON_AddStringToObject(json, "public_encryption_key",
                          public_encryption_key_hex);
  cJSON_AddStringToObject(json, "public_signing_key", public_signing_key_hex);
  cJSON_AddStringToObject(json, "home_path", home_path);
  cJSON_AddStringToObject(json, "home_name", home_component);
  cJSON_AddStringToObject(json, "user_home_path", user_home_path);
  cJSON_AddStringToObject(json, "user_home_name", user_home_component);
  request_body = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  json = NULL;
  if (!request_body) {
    goto cleanup;
  }

  if (send_register_json(ssl, request_body) != 0) {
    goto cleanup;
  }

  response = read_response(ssl);
  if (!response || read_response_body(response, ssl, &response_body) != 0) {
    goto cleanup;
  }

  printf("client register response body: %s\n", response_body);
  if (response->status_code == 201) {
    rc = 0;
    printf("Registration successful for user '%s'\n", username);
  }

cleanup:
  cJSON_Delete(json);
  destroy_message(response);
  free(request_body);
  free(response_body);
  free(home_component);
  free(user_home_component);
  free(user_keys);
  free(sign_keys);
  free(username);
  free(pwd);
  return rc;
}

int logout(SSL* ssl, Session* session) {
  http_message_t* msg = NULL;
  http_message_t* response = NULL;
  char* response_body = NULL;
  int rc = -1;

  if (!ssl || !session || !session->token) {
    return -1;
  }

  msg = init_request();
  if (!msg) {
    return -1;
  }

  msg->method = POST;
  strncpy(msg->path, "/auth/logout", HTTP_MAX_PATH_LEN - 1);
  msg->path[HTTP_MAX_PATH_LEN - 1] = '\0';
  strncpy(msg->auth_token, session->token, sizeof(msg->auth_token) - 1);
  msg->auth_token[sizeof(msg->auth_token) - 1] = '\0';
  msg->content_type = NONE;
  msg->content_length = 0;

  printf("client logout request token: %s\n", session->token);
  send_request(ssl, msg);
  destroy_message(msg);

  response = read_response(ssl);
  if (!response) {
    return -1;
  }

  if (response->content_length > 0 &&
      read_response_body(response, ssl, &response_body) == 0) {
    printf("client logout response body: %s\n", response_body);
  }

  if (response->status_code == 200) {
    rc = 0;
  }

  free(response_body);
  destroy_message(response);
  return rc;
}

Session login(SSL* ssl) {
  Session s;

  memset(&s, 0, sizeof(s));
  printf("Username: ");
  setStdinEcho(true);
  char* username = get_input();
  if (!username) {
    return s;
  }

  printf("Password: ");
  setStdinEcho(false);
  char* pwd = get_input();
  if (!pwd) {
    setStdinEcho(true);
    free(username);
    return s;
  }
  SignKeys* sign_keys = NULL;
  UserKeys* user_keys = NULL;
  char* challenge_hex = NULL;
  unsigned char challenge[crypto_sign_BYTES];
  size_t challenge_len = 0;
  char* signed_challenge = NULL;
  char signature_hex[(crypto_sign_BYTES + crypto_sign_BYTES) * 2 + 1];

  setStdinEcho(true);

  challenge_hex = request_login_challenge(ssl, username);
  if (!challenge_hex) {
    fprintf(stderr, "Failed to fetch login challenge\n");
    free(username);
    free(pwd);
    return s;
  }

  if (hex_decode(challenge_hex, challenge, sizeof(challenge), &challenge_len) != 0) {
    fprintf(stderr, "Failed to decode login challenge\n");
    free(challenge_hex);
    free(username);
    free(pwd);
    return s;
  }
  free(challenge_hex);

  sign_keys = generate_signing_keypair(username, pwd);
  if (!sign_keys) {
    fprintf(stderr, "Failed to derive signing keys\n");
    free(pwd);
    free(username);
    return s;
  }

  user_keys = generate_read_keypair(username, pwd);
  free(pwd);
  if (!user_keys) {
    fprintf(stderr, "Failed to derive encryption keys\n");
    free(sign_keys);
    free(username);
    return s;
  }

  signed_challenge = generate_bytes_signature(challenge, challenge_len, sign_keys);
  if (!signed_challenge) {
    fprintf(stderr, "Failed to sign login challenge\n");
    free(user_keys);
    free(sign_keys);
    free(username);
    return s;
  }

  if (hex_encode((unsigned char*)signed_challenge,
                 crypto_sign_BYTES + challenge_len, signature_hex,
                 sizeof(signature_hex)) != 0) {
    fprintf(stderr, "Failed to encode login signature\n");
    free(signed_challenge);
    free(user_keys);
    free(sign_keys);
    free(username);
    return s;
  }
  free(signed_challenge);

  s.token = submit_login_signature(ssl, username, signature_hex);
  if (!s.token) {
    fprintf(stderr, "Login failed\n");
    free(user_keys);
    free(sign_keys);
    free(username);
    memset(&s, 0, sizeof(s));
    return s;
  }

  s.id = 0;
  s.username = username;
  s.user_keys = user_keys;
  s.sign_keys = sign_keys;
  snprintf(s.cwd, sizeof(s.cwd), "/home/%s", username);
  printf("Login successful. Session token: %s\n", s.token);
  return s;
}

void destroy_session(Session* s) {
  if (!s) {
    return;
  }
  free(s->username);
  free(s->token);
  free(s->user_keys);
  free(s->sign_keys);
  s->username = NULL;
  s->token = NULL;
  s->user_keys = NULL;
  s->sign_keys = NULL;
}
