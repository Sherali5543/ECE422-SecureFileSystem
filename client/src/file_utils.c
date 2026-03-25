#include "file_utils.h"
#include "encryption.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>



void read_file(){
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
    // using README as a demo
    // TODO: actually have this work with the server
    bool can_write = true;

    if(can_write){
        char editor[] = "vi ";
        char filepath[] = "../../README.md";
        strcat(editor, filepath);

        system(editor);
    }
}

void create_file(char* filepath, char* filename, Session* s){
    // Defaults perms for the file will only allow owner to access it
    char template[] = "/tmp/sfs_create_XXXXXX";
    int fd = mkstemp(template);

    if (fd == -1) {
        perror("mkstemp");
        return;
    }
    close(fd); 

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "vi %s", template);
    system(cmd);

    // encrypt the file
    char *file_key = NULL;
    char *encrypted_file = NULL;
    file_key = generate_file_key();
    encrypted_file = encrypt_file(file_key, template);
    unlink(template);

    // wrap file key with user key
    char* wrapped = NULL;
    wrapped = encrypt_wrapped_user_key(s->user_keys, file_key);

    unlink(encrypted_file);
}

void delete_file(){

}

