#ifndef P256_H
#define P256_H

#include "option.h"

int psa_p256_validate_key(const uint8_t *private_key);
int psa_p256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result);
int32_t psa_p256_derive_pk(const uint8_t *private_key, uint8_t *public_key);
int32_t psa_p256_derive_pk_uncompressed(const uint8_t *private_key, uint8_t *public_key);
int32_t psa_p256_sign_hash(const uint8_t *private_key, const uint8_t *hash, size_t hash_length,
			   uint8_t *signature);

#endif
