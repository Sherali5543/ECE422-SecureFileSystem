#include "session.h"
#include "cli_utils.h"

int main(){
    Session session = login();
    cli_loop(session);
}