#include "session.h"
#include "cli_utils.h"
#include "client.c"

int main(void){
  connect_to_server(); // Minimal example. Left here for testing
  Session session = login();
  cli_loop(&session);

  return EXIT_SUCCESS;
}
