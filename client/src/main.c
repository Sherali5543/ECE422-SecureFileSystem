#include "session.h"
#include "cli_utils.h"
#include "client.h"

int main(void){
  char* action = NULL;
  SSL_CTX* ctx = setup_client();
  SSL* ssl = connect_to_server(ctx);

  while (1) {
    Session session;

    printf("\n=== Main Menu ===\n");
    printf("login\n");
    printf("register\n");
    printf("exit\n");
    printf("> ");

    action = get_input();
    if (action == NULL) {
      break;
    }

    if (strcmp(action, "login") == 0) {
      session = login(ssl);
      if (session.token != NULL) {
        cli_loop(ssl, &session);
      }
    } else if (strcmp(action, "register") == 0) {
      if (register_account(ssl) != 0) {
        fprintf(stderr, "Registration failed\n");
      }
    } else if (strcmp(action, "exit") == 0) {
      free(action);
      break;
    } else {
      printf("unknown command: %s\n", action);
    }

    free(action);
    action = NULL;
  }

  disconnect_server(ssl, ctx);

  return EXIT_SUCCESS;
}
