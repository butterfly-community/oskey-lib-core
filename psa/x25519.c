#include "x25519.h"

#include <string.h>
#include "c25519/c25519.h"

int psa_x25519_export_pk_from_secret(const uint8_t *secret32, uint8_t *out33) {
	if (!secret32 || !out33) {
		return -1;
	}
	uint8_t clamped[32];
	memcpy(clamped, secret32, 32);
	c25519_prepare(clamped);

	uint8_t pub[32];
	c25519_smult(pub, c25519_base_x, clamped);

	out33[0] = 0x00;
	memcpy(out33 + 1, pub, 32);
	return 0;
}