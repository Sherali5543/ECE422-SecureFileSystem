#include "cli.c"
#include "session.h"

int main(){
    Session session = login();
    cli_loop(session);
}