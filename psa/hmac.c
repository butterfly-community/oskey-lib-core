#include <psa/crypto.h>
#include "option.h"
#include "psa_init.h"

int32_t psa_hmac_sha512_wrapper(const uint8_t *message, size_t message_len, const uint8_t *key,
				size_t key_len, uint8_t *output)
{
	psa_status_t status = psa_crypto_init_once();
	if (status != PSA_SUCCESS) {
		return status;
	}
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t key_id = 0;
	size_t output_len;

	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_512));
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(key_len));

	status = psa_import_key(&attributes, key, key_len, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_512), message, message_len,
				 output, 64, &output_len);

	psa_destroy_key(key_id);
	return status;
}
