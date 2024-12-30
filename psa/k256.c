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

int psa_normalize_signature(uint8_t *sig)
{
	int ret = 0;
	mbedtls_mpi s, order, half_order;
	mbedtls_ecp_group grp;

	mbedtls_mpi_init(&s);
	mbedtls_mpi_init(&order);
	mbedtls_mpi_init(&half_order);
	mbedtls_ecp_group_init(&grp);

	if (ret == 0) {
		ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
	}

	if (ret == 0) {
		ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
	}
	if (ret == 0) {
		ret = mbedtls_mpi_copy(&order, &grp.N);
	}

	if (ret == 0) {
		ret = mbedtls_mpi_copy(&half_order, &order);
	}
	if (ret == 0) {
		ret = mbedtls_mpi_shift_r(&half_order, 1);
	}

	if (ret == 0) {
		ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
	}
	if (ret == 0 && mbedtls_mpi_cmp_mpi(&s, &half_order) > 0) {
		ret = mbedtls_mpi_sub_mpi(&s, &order, &s);
		if (ret == 0) {
			ret = mbedtls_mpi_write_binary(&s, sig + 32, 32);
		}
	}

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&order);
	mbedtls_mpi_free(&half_order);
	mbedtls_ecp_group_free(&grp);


	return ret;
}

int32_t psa_k256_sign_hash(const uint8_t *private_key, const uint8_t *hash, size_t hash_length,
			   uint8_t *signature)
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
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

	status = psa_import_key(&attributes, private_key, 32, &key_id);
	if (status != PSA_SUCCESS) {
		return status;
	}

	status = psa_sign_hash(key_id, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256), hash,
			       hash_length, signature, 64, &signature_length);
	if (status != PSA_SUCCESS) {
		return status;
	}

	int ret = psa_normalize_signature(signature);

	if (ret != 0) {
		return ret;
	}
	psa_destroy_key(key_id);
	return status;
}

// #include <mbedtls/ecdsa.h>
// #include <mbedtls/entropy.h>
// #include <mbedtls/ctr_drbg.h>
// #include <stdint.h>

// static void ecdsa_cleanup(mbedtls_ecdsa_context *ctx, mbedtls_mpi *sig_r, mbedtls_mpi *sig_s,
//                          mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctr_drbg) {
//     mbedtls_ecdsa_free(ctx);
//     mbedtls_mpi_free(sig_r);
//     mbedtls_mpi_free(sig_s);
//     mbedtls_entropy_free(entropy);
//     mbedtls_ctr_drbg_free(ctr_drbg);
// }

// int32_t psa_k256_sign_hash(const uint8_t *private_key, const uint8_t *hash,
//                           size_t hash_length, uint8_t *signature) {
//     mbedtls_ecdsa_context ctx;
//     mbedtls_mpi sig_r, sig_s;
//     mbedtls_entropy_context entropy;
//     mbedtls_ctr_drbg_context ctr_drbg;
//     int ret;

//     mbedtls_ecdsa_init(&ctx);
//     mbedtls_mpi_init(&sig_r);
//     mbedtls_mpi_init(&sig_s);
//     mbedtls_entropy_init(&entropy);
//     mbedtls_ctr_drbg_init(&ctr_drbg);

//     ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 1;
//     }

//     mbedtls_ecp_keypair_init(&ctx);

//     ret = mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256K1);
//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 2;
//     }

//     ret = mbedtls_mpi_read_binary(&ctx.MBEDTLS_PRIVATE(d), private_key, 32);
//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 3;
//     }

//     ret = mbedtls_ecdsa_sign_det_ext(&ctx.MBEDTLS_PRIVATE(grp),
//                                             &sig_r, &sig_s,
//                                             &ctx.MBEDTLS_PRIVATE(d),
//                                             hash, hash_length,
//                                             MBEDTLS_MD_SHA256,
//                                             mbedtls_ctr_drbg_random,
//                                             &ctr_drbg);

//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 4;
//     }

//     ret = mbedtls_mpi_write_binary(&sig_r, signature, 32);
//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 5;
//     }

//     ret = mbedtls_mpi_write_binary(&sig_s, signature + 32, 32);
//     if(ret != 0) {
//         ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//         return 6;
//     }

//     ecdsa_cleanup(&ctx, &sig_r, &sig_s, &entropy, &ctr_drbg);
//     return 0;
// }
