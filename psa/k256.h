#ifndef __K256_H__
#define __K256_H__

#include "option.h"

int32_t psa_k256_derive_pk(const uint8_t *private_key, uint8_t *public_key);
int32_t psa_k256_derive_pk_uncompressed(const uint8_t *private_key, uint8_t *public_key);
int psa_k256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result);

#endif
