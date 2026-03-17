#include "session.h"
#include <stdio.h>
#include "cli_utils.h"

Session login(){
    printf("Username: ");
    char* username = scan();
    printf("\nPassword: ");
    char* pwd = scan();
    // TODO: Proper username and password check
    printf("\nOk, ill take your word for it!\n");

    Session s;
    s.id = 0;
    s.username = *username;

    return s;
}
