#include "session.h"
#include "cli_utils.h"
#include "client.h"
#include <sodium.h>

int main(void){
  char* action = NULL;
  SSL_CTX* ctx = setup_client();
  SSL* ssl = connect_to_server(ctx);

  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    disconnect_server(ssl, ctx);
    return EXIT_FAILURE;
  }

  while (1) {
    Session session;
    memset(&session, 0, sizeof(session));

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
        run_integrity_check(ssl, &session);
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
