#ifndef X25519_PSA_H
#define X25519_PSA_H

#include "option.h"

int psa_x25519_export_pk_from_secret(const uint8_t *secret32, uint8_t *out33);

#endif