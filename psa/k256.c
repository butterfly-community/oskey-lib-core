#include <psa/crypto.h>
#include <string.h>
#include "option.h"

int32_t psa_k256_derive_pk_uncompressed(const uint8_t *private_key, uint8_t *public_key)
{
	psa_status_t status = psa_crypto_init();
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
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_export_public_key(key_id, public_key, 65, &output_length);
	psa_destroy_key(key_id);

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

int psa_k256_add_num(const uint8_t *num1, const uint8_t *num2, uint8_t *result)
{
	mbedtls_mpi IL, SK, N, R;

	mbedtls_mpi_init(&IL);
	mbedtls_mpi_init(&SK);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&R);

	int ret = mbedtls_mpi_read_binary(&IL, num1, 32);

	if (ret == 0) {
		ret = mbedtls_mpi_read_binary(&SK, num2, 32);
	}
	if (ret == 0) {
		ret = mbedtls_mpi_read_binary(&N, k256_n, 32);
	}

	/* Modular addition: : R = (IL + SK) mod N */
	if (ret == 0) {
		ret = mbedtls_mpi_add_mpi(&R, &IL, &SK);
	}
	if (ret == 0) {
		ret = mbedtls_mpi_mod_mpi(&R, &R, &N);
	}

	if (ret == 0) {
		ret = mbedtls_mpi_write_binary(&R, result, 32);
	}

	mbedtls_mpi_free(&IL);
	mbedtls_mpi_free(&SK);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&R);

	return ret;
}

int32_t psa_k256_sign_message(const uint8_t *private_key, const uint8_t *message,
			      size_t message_length, uint8_t *signature)
{
	size_t signature_length;
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), message, message_length,
				  signature, 64, &signature_length);

	psa_destroy_key(key_id);
	return status;
}

int32_t psa_k256_verify_message(const uint8_t *public_key, const uint8_t *message,
				size_t message_length, const uint8_t *signature)
{
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE);

	status = psa_import_key(&attributes, public_key, 65, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), message, message_length,
				    signature, 64);

	psa_destroy_key(key_id);
	return status;
}
