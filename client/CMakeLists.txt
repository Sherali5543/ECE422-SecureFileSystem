add_executable(client
    src/main.c
    src/cli.c
    src/cli_utils.c
    src/file_utils.c
    src/session.c
    src/encryption.c
)

target_link_libraries(client PRIVATE common)
target_include_directories(client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
