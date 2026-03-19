#include "cli_utils.h"

char* get_input(){
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    read = getline(&line, &len, stdin);
    if(read == -1){
        free(line);
        return NULL;
    }
    if(line[read-1] == '\n'){
        line[read-1] = '\0';
    }

    return line;
}

void str_to_arr(char* str, char* array[], int size){
    char* token = strtok(str, " ");
    int i = 0;

    while(token != NULL && i < size){
        array[i] = token;
        i++;
        token = strtok(NULL, " ");
    }

    // pad out the rest of the array with NULL
    while (i < size){
        array[i] = NULL;
        i++;
    } 
}

void setStdinEcho(bool enable){
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) {
        tty.c_lflag &= ~(tcflag_t)ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}