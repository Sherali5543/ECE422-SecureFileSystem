#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "common_encryption.h"
#include <stdlib.h>

// populates a buffer with cryptographically random bytes
void populate_cryptorandom(char* buf, size_t size);

#endif