#include "file_utils.h"
#include "encryption.h"

void read_file(char* filepath){
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

void write_file(char* filepath){
    // TODO: for now assume we always are allowed to write
    // however we probably need to add communication with the server
    // to verify the user is allowed to write before we let them
    bool can_write = true;

    if(can_write){
        char editor[] = "vi ";
        char filepath[] = "../../README.md";
        strcat(editor, filepath);

        system(editor);
    }
}

void create_file(){

}

void delete_file(){

}

