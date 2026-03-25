#include <string.h>
#include <sodium.h>

#include "encryption.h"

void populate_cryptorandom(char* buf, size_t size){
    randombytes_buf((void * const) buf, (const size_t) size);
}

char* generate_password_hash(char* password){
    char* hashed_password = malloc(crypto_pwhash_STRBYTES);

    if(crypto_pwhash_str(hashed_password, (const char *) password, strlen(password), 
        crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0){
            return NULL;
        }

    return hashed_password;
}

int verify_password(char* hashed_password, char* user_input){
    return crypto_pwhash_str_verify((const char*) hashed_password, (const char * const) user_input, strlen(user_input)) == 0;
}

