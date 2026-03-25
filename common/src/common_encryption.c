#include <string.h>
#include <sodium.h>
#include "common_encryption.h"

char* generate_bytes_hash(char* text){
    char* hash = malloc(crypto_generichash_BYTES);

    crypto_generichash((unsigned char *) hash, sizeof hash, 
                        (const unsigned char *) text, strlen(text), NULL, 0);

    return hash;
}

char* decrypt_hash_signature(char* signature, char* signer_public_key){
    char* hash = malloc(crypto_generichash_BYTES);

    if(crypto_sign_open((unsigned char *) hash, NULL,
                            (const unsigned char *) signature, 
                            crypto_sign_BYTES + crypto_generichash_BYTES, 
                            (const unsigned char *) signer_public_key) != 0){
        return NULL;
    }

    return hash;
}