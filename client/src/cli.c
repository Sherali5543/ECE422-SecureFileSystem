/*
supported commands: 
login, logout, ls, cd, mkdir, create, read, write, rm, and mv
*/

#include "cli_utils.h"
#include "session.h"
#include <sys/stat.h>

#define MAX_ARGS 3
#define PATH_MAX 256

void cli_loop(Session *session){
    char* args[MAX_ARGS];
    char* input;
    char cwd[PATH_MAX];
    getcwd(cwd, sizeof(cwd));

    while (true) {
        printf("%s:%s$ ", session->username, cwd);
        input = get_input();


        if (input == NULL) {
            fprintf(stderr, "Failed to read input\n");
            return;
        }

        str_to_arr(input, args, MAX_ARGS);
        char* cmd = args[0];

        if (strcmp(cmd, "ls") == 0) {
            system("ls -1 -m --color=auto");

        } else if (strcmp(cmd, "cd") == 0) {
            if(args[1] == NULL){
                printf("cd: no arguements provided\n");
                continue;
            } else if (chdir(args[1]) == -1) {
                printf("No such file or directory: %s\n", args[1]);
                continue;
            }
            getcwd(cwd, sizeof(cwd));

        } else if (strcmp(cmd, "mkdir") == 0) {
            if(args[1] == NULL){
                printf("mkdir: no arguements provided\n");
            } else if (mkdir(args[1], 0755) != 0) {
                printf("failed to create dir");
            }

        } else if (strcmp(cmd, "rm") == 0) {
            if(args[1] == NULL){
                printf("rm: no arguements provided\n");
            } else if (remove(args[1]) != 0) {
                printf("failed to remove file: %s\n", args[1]);
            }

        } else if (strcmp(cmd, "mv") == 0) {
            if (args[1] == NULL || args[2] == NULL) {
                printf("mv: no arguements provided\n");
            }
            strcat(args[2], "/");
            strcat(args[2], args[1]);
            if (rename(args[1], args[2]) != 0){
                printf("failed to move file\n");
            }

        } else if (strcmp(cmd, "logout") == 0) {
            destroy_session(session);
            free(input);
            break;
        } else {
            printf("unknown command: %s\n", args[0]);
        }

        free(input);
    }
}
