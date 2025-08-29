cmake_minimum_required(VERSION 3.20.0)

project(wallets)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

find_package(MbedTLS REQUIRED)


add_compile_options(
        -Wall
        -Wreturn-local-addr
)

include(${CMAKE_CURRENT_SOURCE_DIR}/psa/CMakeLists.txt)

target_link_libraries(crypto STATIC MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)

install(
    TARGETS crypto
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}
)
