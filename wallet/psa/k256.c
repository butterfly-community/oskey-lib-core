#include <psa/crypto.h>
#include <string.h>

#include "k256.h"
#include "psa_init.h"
#include "scalar.h"

int32_t psa_k256_derive_pk_uncompressed(const uint8_t *private_key, uint8_t *public_key)
{
	psa_status_t status = psa_crypto_init_once();
	if (status != PSA_SUCCESS) {
		return status;
	}
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t output_length;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_export_public_key(key_id, public_key, 65, &output_length);
	psa_status_t destroy_status = psa_destroy_key(key_id);
	if (status == PSA_SUCCESS) {
		status = destroy_status;
	}
	if (status == PSA_SUCCESS && output_length != 65) {
		return PSA_ERROR_DATA_INVALID;
	}

	return status;
}

int32_t psa_k256_derive_pk(const uint8_t *private_key, uint8_t *public_key)
{
	uint8_t u_pk[65];
	psa_status_t status = psa_k256_derive_pk_uncompressed(private_key, u_pk);

	if (status != PSA_SUCCESS) {
		return status;
	}
	public_key[0] = (u_pk[64] & 1) ? 0x03 : 0x02;
	memcpy(public_key + 1, u_pk + 1, 32);

	return PSA_SUCCESS;
}

// K256 curve order
static const uint8_t k256_n[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				   0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
				   0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

// K256 curve order divided by two
static const uint8_t k256_half_n[32] = {
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4,
	0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
};

int psa_k256_validate_key(const uint8_t *private_key)
{
	return psa_scalar_is_valid(private_key, k256_n) ? 0 : -1;
}

int psa_k256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result)
{
	return psa_scalar_add(num1, num2, k256_n, result);
}

static void psa_normalize_signature(uint8_t *sig)
{
	uint8_t *s = sig + 32;

	if (psa_scalar_cmp(s, k256_half_n) > 0) {
		uint8_t normalized[32];
		memcpy(normalized, k256_n, sizeof(normalized));
		psa_scalar_sub(normalized, s);
		memcpy(s, normalized, sizeof(normalized));
	}
}

int32_t psa_k256_sign_hash(const uint8_t *private_key, const uint8_t *hash, size_t hash_length,
			   uint8_t *signature)
{
	size_t signature_length;
	psa_status_t status = psa_crypto_init_once();
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_sign_hash(key_id, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), hash,
			       hash_length, signature, 64, &signature_length);
	psa_status_t destroy_status = psa_destroy_key(key_id);
	if (status == PSA_SUCCESS) {
		status = destroy_status;
	}
	if (status == PSA_SUCCESS && signature_length != 64) {
		return PSA_ERROR_DATA_INVALID;
	}
	if (status == PSA_SUCCESS) {
		psa_normalize_signature(signature);
	}

	return status;
}
