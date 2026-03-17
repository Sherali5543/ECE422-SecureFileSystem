#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include "cli_utils.h"

Session* login(){
    printf("Username: ");
    char* username = scan();
    printf("\nPassword: ");
    char* pwd = scan();
    // TODO: Proper username and password check
    printf("\nOk, ill take your word for it!\n");

    Session* s = malloc(sizeof(Session));
    s->id = 0;
    s->username = *username;
    if (!s) return NULL;
}

void destroy_session(Session *s){   
    if(!s) return;
    free(s);
}