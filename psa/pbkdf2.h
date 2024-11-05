#ifndef __PBKDF2_H__
#define __PBKDF2_H__

#include "option.h"

int32_t psa_pbkdf2_hmac_sha512_wrapper(const uint8_t *password, size_t password_len,
					const uint8_t *salt, size_t salt_len, uint8_t *output,
					size_t rounds);

#endif
