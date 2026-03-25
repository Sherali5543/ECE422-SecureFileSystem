find_package(SQLite3 REQUIRED)

add_executable(server
    src/main.c
    src/encryption.c
    src/server.c
    src/server_context.c
    src/db/db.c
    src/db/schema_helper.c
    src/routing/routing.c
)

target_link_libraries(server PRIVATE
  common
  SQLite::SQLite3
)

target_include_directories(server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
