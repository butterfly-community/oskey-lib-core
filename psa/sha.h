#ifndef __SHA_H__
#define __SHA_H__

#include "option.h"

bool psa_sha256_wrapper(uint8_t *hash, const uint8_t *input, size_t input_len);
bool psa_sha512_wrapper(uint8_t *hash, const uint8_t *input, size_t input_len);

#endif
