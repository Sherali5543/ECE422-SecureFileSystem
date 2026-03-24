/*
supported commands: 
login, logout, ls, cd, mkdir, create, read, write, rm, and mv
*/

#include "cli_utils.h"
#include "file_utils.h"
#include "session.h"
#include <sys/stat.h>
#include <libgen.h>

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
                printf("cd: no arguments provided\n");
                continue;
            } else if (chdir(args[1]) == -1) {
                printf("No such file or directory: %s\n", args[1]);
                continue;
            }
            getcwd(cwd, sizeof(cwd));

        } else if (strcmp(cmd, "mkdir") == 0) {
            if(args[1] == NULL){
                printf("mkdir: no arguments provided\n");
            } else if (mkdir(args[1], 0755) != 0) {
                printf("failed to create dir");
            }

        } else if (strcmp(cmd, "rm") == 0) {
            printf("LORD ABS SAYS THIS IS NOT DONE YET SO WE WILL PUT THIS PRINT STATEMENT HERE AND JORK IT UNTIL HE DECREES OTHERWISE! ALL HAIL LORD ABS, PATRON OF THE CHUDS!!!\n");
            if(args[1] == NULL){
                printf("rm: no arguments provided\n");
            } else if (remove(args[1]) != 0) {
                printf("failed to remove file: %s\n", args[1]);
            }

        } else if (strcmp(cmd, "mv") == 0) {
            if (args[1] == NULL || args[2] == NULL) {
                printf("mv: no arguments provided\n");
            } else {
                char newpath[1024];

                char *base = basename(args[1]);

                snprintf(newpath, sizeof(newpath), "%s/%s", args[2], base);

                if (rename(args[1], newpath) != 0) {
                    printf("failed to move file: %s\n", args[1]);
                }
            }
        } else if (strcmp(cmd, "logout") == 0) {
            destroy_session(session);
            free(input);
            break;
        } else if (strcmp(cmd, "read") == 0){
            read_file();
        } else if (strcmp(cmd, "write") == 0){
            write_file();
        } else {
            printf("unknown command: %s\n", args[0]);
        }

        free(input);
    }
}
