#include <psa/crypto.h>
#include <string.h>

#include "p256.h"
#include "psa_init.h"

static const uint8_t p256_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
	0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

static int scalar_cmp(const uint8_t *a, const uint8_t *b)
{
	uint32_t greater = 0;
	uint32_t less = 0;

	for (size_t i = 0; i < 32; i++) {
		const uint32_t undecided = 1U ^ (greater | less);

		greater |= ((uint32_t)b[i] - a[i]) >> 31 & undecided;
		less |= ((uint32_t)a[i] - b[i]) >> 31 & undecided;
	}
	return (int)greater - (int)less;
}

static bool scalar_is_zero(const uint8_t *value)
{
	uint8_t result = 0;

	for (size_t i = 0; i < 32; i++) {
		result |= value[i];
	}
	return result == 0;
}

static void scalar_sub(uint8_t *value, const uint8_t *subtrahend)
{
	uint16_t borrow = 0;

	for (size_t i = 32; i > 0; i--) {
		const uint16_t minuend = value[i - 1];
		const uint16_t sub = (uint16_t)subtrahend[i - 1] + borrow;
		value[i - 1] = (uint8_t)(minuend - sub);
		borrow = minuend < sub;
	}
}

int psa_p256_validate_key(const uint8_t *private_key)
{
	return !scalar_is_zero(private_key) && scalar_cmp(private_key, p256_n) < 0 ? 0 : -1;
}

int psa_p256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result)
{
	uint16_t carry = 0;

	if (psa_p256_validate_key(num1) || scalar_cmp(num2, p256_n) >= 0) {
		return -1;
	}

	for (size_t i = 32; i > 0; i--) {
		const uint16_t sum = (uint16_t)num1[i - 1] + num2[i - 1] + carry;
		result[i - 1] = (uint8_t)sum;
		carry = sum >> 8;
	}

	if (carry != 0 || scalar_cmp(result, p256_n) >= 0) {
		scalar_sub(result, p256_n);
	}

	return scalar_is_zero(result) ? -1 : 0;
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
