/*
supported commands: 
login, logout, ls, cd, mkdir, create, read, write, rm, and mv
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "cli_utils.h"
#include "session.h"

#define MAX_ARGS 3

void cli_loop(Session* session){
    char* args[MAX_ARGS];
    char* input;

    while (true) {
        printf("username:~/path$ ");
        input = scan();

        if (input == NULL) {
            fprintf(stderr, "Failed to read input\n");
            return;
        }

        str_to_arr(input, args, MAX_ARGS);
        char* cmd = args[0];

        if (strcmp(cmd, "ls") == 0) {
            printf("'ls' not yet implemented!\n");
        } else if (strcmp(cmd, "cd") == 0) {
            printf("'cd' not yet implemented!\n");
        } else if (strcmp(cmd, "mkdir") == 0) {
            printf("'mkdir' not yet implemented!\n");
        } else if (strcmp(cmd, "rm") == 0) {
            printf("'rm' not yet implemented!\n");
        } else if (strcmp(cmd, "mv") == 0) {
            printf("'mv' not yet implemented!\n");
        } else if (strcmp(cmd, "logout") == 0) {
            break;
        } else {
            printf("unknown command: %s\n", args[0]);
        }

        free(input);
    }
}
