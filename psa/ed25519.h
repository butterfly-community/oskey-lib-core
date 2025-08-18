#ifndef ED25519_PSA_H
#define ED25519_PSA_H

#include "option.h"

int psa_ed25519_export_pk_from_seed(const uint8_t *seed32, uint8_t *out33);
int psa_ed25519_sign_from_seed(const uint8_t *seed32, const uint8_t *msg, size_t msg_len, uint8_t *sig64);

#endif