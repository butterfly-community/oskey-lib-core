#include "ed25519.h"

#include <string.h>
#include "c25519/edsign.h"

int psa_ed25519_export_pk_from_seed(const uint8_t *seed32, uint8_t *out33) {
	if (!seed32 || !out33) {
		return -1;
	}
	uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
	edsign_sec_to_pub(pub, seed32);
	out33[0] = 0x00;
	memcpy(out33 + 1, pub, EDSIGN_PUBLIC_KEY_SIZE);
	return 0;
}

int psa_ed25519_sign_from_seed(const uint8_t *seed32, const uint8_t *msg, size_t msg_len, uint8_t *sig64) {
	if (!seed32 || !msg || !sig64) {
		return -1;
	}
	uint8_t pub[EDSIGN_PUBLIC_KEY_SIZE];
	edsign_sec_to_pub(pub, seed32);
	edsign_sign(sig64, pub, seed32, msg, msg_len);
	return 0;
}