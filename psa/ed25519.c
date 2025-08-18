#include "ed25519.h"

#include <string.h>
#include "compact25519.h"

int psa_ed25519_export_pk_from_seed(const uint8_t *seed32, uint8_t *out33) {
	if (!seed32 || !out33) return -1;

	uint8_t seed[32];
	memcpy(seed, seed32, 32);

	uint8_t priv[64], pub[32];
	compact_ed25519_keygen(priv, pub, seed);

	out33[0] = 0x00;
	memcpy(out33 + 1, pub, 32);
	return 0;
}

int psa_ed25519_sign_from_seed(const uint8_t *seed32, const uint8_t *msg, size_t msg_len, uint8_t *sig64) {
	if (!seed32 || !msg || !sig64) return -1;

	uint8_t seed[32];
	memcpy(seed, seed32, 32);

	uint8_t priv[64], pub[32];
	compact_ed25519_keygen(priv, pub, seed);

	compact_ed25519_sign(sig64, priv, msg, msg_len);
	return 0;
}