add_library(crypto STATIC)

target_sources(
  crypto
  PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/bip39.c
  ${CMAKE_CURRENT_LIST_DIR}/bip32.c
  ${CMAKE_CURRENT_LIST_DIR}/codec/base58.c
  ${CMAKE_CURRENT_LIST_DIR}/test.c)
