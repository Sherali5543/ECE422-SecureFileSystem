#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>

#include "common_encryption.h"

extern const int WRAPPED_USER_KEY_SIZE;
extern const int WRAPPED_GROUP_KEY_SIZE;

typedef struct UserKeys {
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
} UserKeys;

typedef struct SignKeys {
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
} SignKeys;

// The user's pair is a public encrypt keypair, generated deterministically
// using the user's username and plaintext password
UserKeys* generate_read_keypair(char* username, char* password);

// The user's pair is a public encrypt keypair, generated deterministically
// using the user's username and plaintext password
SignKeys* generate_signing_keypair(char* username, char* password);

// The file key uses xchacha real smooth take it back now yall
// to randomly generate a shared secret key
char* generate_file_key();

// take a wild guess
// this key is symmetric using whatever algo secretbox is
char* generate_group_key();


// encrypts a key using a user's public key
//
// used for:
// - wrapping file keys with the owner's public
// - wrapping group keys with the members' public
char* encrypt_wrapped_user_key(UserKeys* user_keys, char* main_key);

// decrypts a key using a user's public key
//
// used for:
// - unwrapping file keys with the owner's public
// - unwrapping group keys with the members' public
//
// returns:
// - the unwrapped key if successful
// - null if unsuccessful
char* decrypt_wrapped_user_key(UserKeys* user_keys, char* encrypted_key);


// wraps the file key using the group key
char* encrypt_file_group_key(char* file_key, char* group_key);

// unwraps the file key using the group key
//
// returns:
// - the unwrapped file key if successful
// - null if unwrapping was unsuccessful
char* decrypt_file_group_key(char* group_key, char* encrypted_key);

// generates a hash of the specified filepath
char* generate_file_hash(char* filepath);

// generates the signature of the specified hash by encrypting
// it with the user's signing keys
char* generate_hash_signature(char* hash, SignKeys* sign_keys);

// signs an arbitrary byte buffer using the user's signing keys
char* generate_bytes_signature(const unsigned char* bytes, size_t len,
                               SignKeys* sign_keys);

// decrypts the specified file using the given file key
//
// returns the filepath to the encrypted temp file
//
// must call unlink(filepath); when done using the file to destroy it
char* encrypt_file(char* file_key, char* filepath);


// decrypts the specified file using the file_key
//
// returns the filepath to the decrypted temp file
//
// must call unlink(file_path) when done using the file to destroy it
char* decrypt_file(char* file_key, char* filepath);

int test_encryption();

#endif
