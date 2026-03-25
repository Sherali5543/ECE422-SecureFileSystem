#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "common_encryption.h"
#include <stdlib.h>

// populates a buffer with cryptographically random bytes
void populate_cryptorandom(char* buf, size_t size);

// Hashes a user's password to be used for storing in the database
char* generate_password_hash(char* password);

// Verifies a user's password against the hashed password
// 
// returns 1 if true, 0 if false
int verify_password(char* hashed_password, char* user_input);

#endif