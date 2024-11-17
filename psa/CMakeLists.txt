add_library(crypto STATIC)

target_sources(
  crypto
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/hash.c
  ${CMAKE_CURRENT_LIST_DIR}/pbkdf2.c
  ${CMAKE_CURRENT_LIST_DIR}/hmac.c
  ${CMAKE_CURRENT_LIST_DIR}/k256.c)
