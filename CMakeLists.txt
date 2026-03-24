cmake_minimum_required(VERSION 3.16)

project(SecureFS C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(_POSIX_C_SOURCE=200809L)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion)

add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)
