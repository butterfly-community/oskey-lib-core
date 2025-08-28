#include <psa/crypto.h>
#include "x25519.h"
#include <string.h>
#include "compact25519.h"

int psa_x25519_export_pk_from_secret(const uint8_t *secret32, uint8_t *out33)
{
	if (!secret32 || !out33) {
		return -1;
	}

	uint8_t seed[32];
	memcpy(seed, secret32, 32);

	uint8_t priv[32], pub[32];
	compact_x25519_keygen(priv, pub, seed);

	out33[0] = 0x00;
	memcpy(out33 + 1, pub, 32);
	return 0;
}