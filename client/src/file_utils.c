#include "file_utils.h"

void read_file(){
    // assume file is decrypted ATM
    // using README as a demo
    FILE* fptr;
    fptr = fopen("../../README.md", "r");
    if(fptr == NULL){
        printf("Failed to open file\n");
        return;
    }
    
    char line[256];
    while(fgets(line, sizeof(line), fptr)){
        printf("%s",line);
    }
    fclose(fptr);
}

void write_file(){
    // make a temp file the user writes into.
    // if they are different and the user doesnt 
    // have permission to write throw error
    char editor[] = "vi ";
    char filepath[] = "../../README.md";
    strcat(editor, filepath);

    system(editor);
}

void create_file(){

}

void delete_file(){

}

