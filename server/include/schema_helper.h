#ifndef SERVER_SCHEMA_HELPER_H
#define SERVER_SCHEMA_HELPER_H

#include <sqlite3.h>

int run_schema(sqlite3* db, const char* schema_path);

#endif
