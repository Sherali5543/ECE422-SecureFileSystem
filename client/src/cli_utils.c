#include "cli_utils.h"

char* scan(){
    int c;
    int size = 16;
    int i = 0;

    char *string = malloc(size);
    if (string == NULL)
        return NULL;

    while ((c = getchar()) != '\n' && c != EOF) {
        if (i >= size - 1) {
            size *= 2;
            char *temp = realloc(string, size);
            if (temp == NULL) {
                free(string);
                return NULL;
            }
            string = temp;
        }
        string[i++] = (char)c;
    }

    string[i] = '\0';
    return string;
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
        tty.c_lflag &= ~ECHO;
    } else {
        tty.c_lflag |= ECHO;
    }
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}