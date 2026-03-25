#include "session.h"
#include "cli_utils.h"

Session login(){
    printf("Username: ");
    setStdinEcho(true);
    char* username = get_input();

    printf("Password: ");
    setStdinEcho(false);
    char* pwd = get_input();

    // TODO: Proper username and password check
    printf("\nOk, ill take your word for it! (Password we read was: %s)\n", pwd);
    setStdinEcho(true);

    Session s;
    s.id = 0;
    s.username = username;
    free(pwd);

    return s;
}

void destroy_session(Session *s){
    free(s->username);
}
