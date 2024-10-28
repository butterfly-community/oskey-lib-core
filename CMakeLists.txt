cmake_minimum_required(VERSION 3.20.0)

project(test)

find_package(MbedTLS REQUIRED)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(${CMAKE_CURRENT_SOURCE_DIR}/crypto/CMakeLists.txt)

target_link_libraries(crypto STATIC MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)

install(
    TARGETS crypto
    ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}
)