#include <stdbool.h>
#include <psa/crypto.h>

bool psa_sha256_wrapper(uint8_t *hash, const uint8_t *input, size_t input_len)
{
	psa_status_t status;
	size_t hash_len;

	status = psa_hash_compute(PSA_ALG_SHA_256, input, input_len, hash, 32, &hash_len);

	return (status == PSA_SUCCESS && hash_len == 32);
}


bool psa_sha512_wrapper(uint8_t *hash, const uint8_t *input, size_t input_len)
{
	psa_status_t status;
	size_t hash_len;

	status = psa_hash_compute(PSA_ALG_SHA_512, input, input_len, hash, 64, &hash_len);

	return (status == PSA_SUCCESS && hash_len == 64);
}
