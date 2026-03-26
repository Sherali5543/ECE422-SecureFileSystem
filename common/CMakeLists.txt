find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(LLHTTP REQUIRED libllhttp)
pkg_check_modules(CJSON REQUIRED libcjson)

add_library(common 
     src/tls.c
     src/http.c
     src/http_messages.c
     src/common_encryption.c
)

target_include_directories(common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${LLHTTP_INCLUDE_DIRS}
    ${CJSON_INCULDE_DIRS}
)

target_link_directories(common PUBLIC
    ${SODIUM_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
    ${LLHTTP_LIBRARY_DIRS}
)

target_link_libraries(common PUBLIC
    ${SODIUM_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${LLHTTP_LIBRARIES}
    ${CJSON_LIBRARIES}
)

target_compile_options(common PUBLIC 
    ${SODIUM_CFLAGS_OTHER}
    ${OPENSSL_CFLAGS_OTHER}
)
