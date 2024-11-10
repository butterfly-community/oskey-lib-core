#ifndef __HMAC_H__
#define __HMAC_H__

#include "option.h"

int32_t psa_hmac_sha512_wrapper(const uint8_t *message, size_t message_len,
                               const uint8_t *key, size_t key_len,
                               uint8_t *output);

#endif
