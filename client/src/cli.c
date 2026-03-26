/*
supported commands:
login, logout, ls, cd, mkdir, create, read, write, rm, and mv
*/

#include "cjson/cJSON.h"
#include "cli_utils.h"
#include "http.h"
#include "session.h"

#define MAX_ARGS 3

static void create_file_command(SSL* ssl, const char* filepath) {
  http_message_t* req = init_request();
  http_message_t* res = NULL;
  cJSON* json = NULL;
  char* body = NULL;

  req->method = POST;
  strncpy(req->path, "/files", HTTP_MAX_PATH_LEN);
  req->content_type = JSON;

  strncpy(req->auth_token, "test-token-alice-123", HTTP_MAX_TOKEN_LEN - 1);
  req->auth_token[HTTP_MAX_TOKEN_LEN - 1] = '\0';

  strncpy(req->connection, "close", HTTP_MAX_HEADER_VALUE - 1);

  json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "filepath", filepath);

  body = cJSON_PrintUnformatted(json);
  req->content_length = strlen(body);

  send_request(ssl, req);
  tls_write(ssl, body, req->content_length);

  res = read_response(ssl);

  if (res && res->content_length > 0) {
    char* resp_body = calloc(res->content_length + 1, 1);
    tls_read(ssl, resp_body, res->content_length);
    printf("response body: %s\n", resp_body);
    free(resp_body);
  }

  destroy_message(req);
  destroy_message(res);
  cJSON_Delete(json);
  free(body);
}
void cli_loop(Session* session, SSL* ssl) {
  char* args[MAX_ARGS];
  char* input;

  while (true) {
    printf("%s:~/path$ ", session->username);
    input = get_input();

    if (input == NULL) {
      fprintf(stderr, "Failed to read input\n");
      return;
    }

    str_to_arr(input, args, MAX_ARGS);
    char* cmd = args[0];

    if (strcmp(cmd, "ls") == 0) {
      printf("'ls' not yet implemented!\n");
    } else if (strcmp(cmd, "cd") == 0) {
      printf("'cd' not yet implemented!\n");
    } else if (strcmp(cmd, "mkdir") == 0) {
      printf("'mkdir' not yet implemented!\n");
    } else if (strcmp(cmd, "rm") == 0) {
      printf("'rm' not yet implemented!\n");
    } else if (strcmp(cmd, "mv") == 0) {
      printf("'mv' not yet implemented!\n");
    } else if (strcmp(cmd, "create") == 0) {
      if (args[1] == NULL) {
        printf("usage: create <absolute-path>\n");
      } else {
        create_file_command(ssl, args[1]);
      }
    } else if (strcmp(cmd, "logout") == 0) {
      destroy_session(session);
      free(input);
      break;
    } else {
      printf("unknown command: %s\n", args[0]);
    }

    free(input);
  }
}
