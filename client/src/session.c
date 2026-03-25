#include "session.h"

#include "cjson/cJSON.h"
#include "cli_utils.h"
#include "http.h"
#include "tls.h"

Session login(SSL* ssl) {
  printf("Username: ");
  setStdinEcho(true);
  char* username = get_input();

  printf("Password: ");
  setStdinEcho(false);
  char* pwd = get_input();

  // TODO: Proper username and password check
  printf("Building request\n");
  http_message_t* msg = init_request();
  msg->method = POST;
  strncpy(msg->path, "/auth/login", HTTP_MAX_PATH_LEN);
  msg->content_type = JSON;
  cJSON* json = cJSON_CreateObject();
  cJSON_AddStringToObject(json, "username", username);
  cJSON_AddStringToObject(json, "password", pwd);

  char* body = cJSON_PrintUnformatted(json);
  msg->content_length = strlen(body);

  printf("Sending password\n");
  send_request(ssl, msg);
  tls_write(ssl, body, strlen(body));
  destroy_message(msg);
  free(body);
  cJSON_Delete(json);
  printf("reading response\n");
  msg = read_response(ssl);
  free(msg);
  printf("\nOk, ill take your word for it! (Password we read was: %s)\n", pwd);
  setStdinEcho(true);

  Session s;
  s.id = 0;
  s.username = username;
  free(pwd);

  return s;
}

void destroy_session(Session* s) { free(s->username); }
