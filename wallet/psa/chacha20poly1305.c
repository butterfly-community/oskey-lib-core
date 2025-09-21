#include <psa/crypto.h>
#include <string.h>
#include "option.h"
#include "psa_init.h"
#include "chacha20poly1305.h"

int32_t psa_chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
				     const uint8_t *plaintext, size_t plaintext_len,
				     uint8_t *ciphertext, size_t ciphertext_size,
				     size_t *ciphertext_len)
{
	psa_status_t status = psa_crypto_init_once();
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);

	status = psa_import_key(&attributes, key, 32, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305, nonce, 12, NULL, 0, plaintext,
				  plaintext_len, ciphertext, ciphertext_size, ciphertext_len);

	psa_destroy_key(key_id);

	return status;
}

int32_t psa_chacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
				     const uint8_t *ciphertext, size_t ciphertext_len,
				     uint8_t *plaintext, size_t plaintext_size,
				     size_t *plaintext_len)
{
	psa_status_t status = psa_crypto_init_once();
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_CHACHA20);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_algorithm(&attributes, PSA_ALG_CHACHA20_POLY1305);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);

	status = psa_import_key(&attributes, key, 32, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305, nonce, 12, NULL, 0, ciphertext,
				  ciphertext_len, plaintext, plaintext_size, plaintext_len);

	psa_destroy_key(key_id);

	return status;
}