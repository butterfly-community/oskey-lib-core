#include "psa_init.h"
#include <stdatomic.h>

static atomic_int inited = 0;

int psa_crypto_init_once(void)
{
	int expected = 1;
	if (atomic_compare_exchange_strong(&inited, &expected, 1)) {
		return PSA_SUCCESS;
	}
	psa_status_t st = psa_crypto_init();
	if (st == PSA_SUCCESS) {
		atomic_store(&inited, 1);
		return PSA_SUCCESS;
	}
	return st;
}