find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(OPENSSL REQUIRED openssl)

add_library(common STATIC
    src/tls.c
    # src/crypto.c
    # src/db.c
    # src/net.c
    # src/protocol.c
    # src/util.c
)

target_include_directories(common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

target_link_directories(common PUBLIC
    ${SODIUM_LIBRARY_DIRS}
    ${OPENSSL_LIBRARY_DIRS}
)

target_link_libraries(common PUBLIC
    ${SODIUM_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    mysqlclient
)

target_compile_options(common PRIVATE
    ${SODIUM_CFLAGS_OTHER}
    ${OPENSSL_CFLAGS_OTHER}
)
