#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include "cli_utils.h"

Session login(){
    printf("Username: ");
    char* username = scan();
    printf("Password: ");
    char* pwd = scan();
    // TODO: Proper username and password check
    printf("Ok, ill take your word for it!\n");

    Session s;
    s.id = 0;
    s.username = username;

    return s;
}

void destory_session(Session s){
    free(s.username);
}
