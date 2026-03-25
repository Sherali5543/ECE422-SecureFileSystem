#include <string.h>
#include <sodium.h>

#include "encryption.h"

void populate_cryptorandom(char* buf, size_t size){
    randombytes_buf((void * const) buf, (const size_t) size);
}
