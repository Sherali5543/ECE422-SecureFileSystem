#ifndef FILE_UTILS
#define FILE_UTILS

#include "session.h"

void read_file();
void write_file();
void create_file(char* filepath, char* filename, Session* s);
void delete_file();

#endif