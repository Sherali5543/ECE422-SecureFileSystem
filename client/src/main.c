#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ARGS 3

static char pwd;

/*
    Calling this function will return when the user makes an input. 
    It will dynamically allocate and return the users input.

    NOTE: Remember to FREE THE INPUT when you are done, 
    otherwise I will find you and fart on your pillow :P
*/
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

/*
    Takes an string input, splits by spaces and returns a resulting array.
*/
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
        i++
    } 
}

int main(){
    char* args[MAX_ARGS];

    char* input = scan();
    if (input == NULL) {
        fprintf(stderr, "Failed to read input\n");
        return 1;
    }
    str_to_arr(input, args, MAX_ARGS);

    char* cmd = args[0];
    if (strcmp(cmd, "ls") == 0) {
        printf("we hit ls!\n");
    } else if (strcmp(cmd, "cd") == 0) {
        printf("we hit cd!\n");
    } else if (strcmp(cmd, "mkdir") == 0) {
        printf("we hit mkdir!\n");
    } else if (strcmp(cmd, "rm") == 0) {
        printf("we hit rm!\n");
    } else if (strcmp(cmd, "mv") == 0) {
        printf("we hit mv!\n");
    } else {
        printf("unknown command: %s\n", args[0]);
    }

    free(input);
}