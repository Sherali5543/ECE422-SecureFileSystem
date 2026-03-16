add_executable(server
    src/main.c
    src/auth.c
    src/routes.c
    src/storage.c
)

target_link_libraries(server PRIVATE common)
