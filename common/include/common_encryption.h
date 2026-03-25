#ifndef COMMON_ENCRYPTION_H
#define COMMON_ENCRYPTION_H

// generates a hash string based off of the provided text
char* generate_str_hash(char* text);

// decrypts a hash signature using the signer's public key
// 
// returns the decrypted hash
char* decrypt_hash_signature(char* signature, char* signer_public_key);

#endif

