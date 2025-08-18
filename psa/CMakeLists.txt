add_library(crypto STATIC)

target_sources(
  crypto
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/hash.c
  ${CMAKE_CURRENT_LIST_DIR}/pbkdf2.c
  ${CMAKE_CURRENT_LIST_DIR}/hmac.c
  ${CMAKE_CURRENT_LIST_DIR}/k256.c
  ${CMAKE_CURRENT_LIST_DIR}/ed25519.c
  ${CMAKE_CURRENT_LIST_DIR}/x25519.c
  ${CMAKE_CURRENT_LIST_DIR}/compact25519/src/compact25519.c
  ${CMAKE_CURRENT_LIST_DIR}/psa_init.c)

target_include_directories(
  crypto
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}
  ${CMAKE_CURRENT_LIST_DIR}/compact25519/src)