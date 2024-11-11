#include <psa/crypto.h>
#include "option.h"

int32_t psa_pbkdf2_hmac_sha512_wrapper(const uint8_t *password, size_t password_len,
				       const uint8_t *salt, size_t salt_len, uint8_t *output,
				       size_t rounds)
{

	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return status;
	}
	// Init PSA operation
	psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

	// Setup add alg
	status = psa_key_derivation_setup(&operation, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_512));

	// Add rounds
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_integer(&operation, PSA_KEY_DERIVATION_INPUT_COST,
							  rounds);
	}
	// Add salt
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT,
							salt, salt_len);
	}
	// Add password
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_input_bytes(
			&operation, PSA_KEY_DERIVATION_INPUT_PASSWORD, password, password_len);
	}
	// Add maximum capacity
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_set_capacity(&operation, 64);
	}
	// Generate output
	if (status == PSA_SUCCESS) {
		status = psa_key_derivation_output_bytes(&operation, output, 64);
	}
	// If no success abort
	if (status != PSA_SUCCESS) {
		psa_key_derivation_abort(&operation);
		return status;
	}

	return PSA_SUCCESS;
}
