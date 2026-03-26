#include "session.h"
#include "cli_utils.h"
#include "client.h"

int main(void){
  SSL_CTX* ctx = setup_client();
  SSL* ssl = connect_to_server(ctx);
  Session session = login(ssl);
  cli_loop(&session);
  disconnect_server(ssl, ctx);

  return EXIT_SUCCESS;
}
