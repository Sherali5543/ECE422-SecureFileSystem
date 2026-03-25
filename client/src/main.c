#include "session.h"
#include "cli_utils.h"
#include "client.c"
#include "encryption.h"

int main(void){
  SSL_CTX* ctx = setup_client();
  SSL* ssl = connect_to_server(ctx);
  do_something(ssl);
  Session session = login();
  cli_loop(&session);
  disconnect_server(ssl, ctx);

  return EXIT_SUCCESS;
}
