#ifndef COMMON_ENCRYPTION_H
#define COMMON_ENCRYPTION_H

#include <stdlib.h>

// generates a hash string based off of the provided 
// bytes buffer and its length 
char* generate_bytes_hash(char* buf, size_t len);

// decrypts a hash signature using the signer's public key
// 
// returns the decrypted hash
char* decrypt_hash_signature(char* signature, char* signer_public_key);

#endif

