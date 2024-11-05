add_library(crypto STATIC)

target_sources(
  crypto
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/sha.c)
