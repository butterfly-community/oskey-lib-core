#include <psa/crypto.h>
#include <string.h>

#include "p256.h"
#include "psa_init.h"
#include "scalar.h"

static const uint8_t p256_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
	0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

int psa_p256_validate_key(const uint8_t *private_key)
{
	return psa_scalar_is_valid(private_key, p256_n) ? 0 : -1;
}

int psa_p256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result)
{
	return psa_scalar_add(num1, num2, p256_n, result);
}

int32_t psa_p256_derive_pk_uncompressed(const uint8_t *private_key, uint8_t *public_key)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t output_length;
	psa_status_t status = psa_crypto_init_once();

	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_export_public_key(key_id, public_key, 65, &output_length);
	psa_destroy_key(key_id);
	if (status == PSA_SUCCESS && output_length != 65) {
		return PSA_ERROR_DATA_INVALID;
	}
	return status;
}

int32_t psa_p256_derive_pk(const uint8_t *private_key, uint8_t *public_key)
{
	uint8_t uncompressed[65];
	psa_status_t status = psa_p256_derive_pk_uncompressed(private_key, uncompressed);

	if (status != PSA_SUCCESS) {
		return status;
	}

	public_key[0] = (uncompressed[64] & 1) ? 0x03 : 0x02;
	memcpy(public_key + 1, uncompressed + 1, 32);
	return PSA_SUCCESS;
}

int32_t psa_p256_sign_hash(const uint8_t *private_key, const uint8_t *hash, size_t hash_length,
			   uint8_t *signature)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;
	size_t signature_length;
	psa_status_t status = psa_crypto_init_once();

	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, hash_length, signature,
			       64, &signature_length);
	psa_destroy_key(key_id);
	if (status == PSA_SUCCESS && signature_length != 64) {
		return PSA_ERROR_DATA_INVALID;
	}
	return status;
}
