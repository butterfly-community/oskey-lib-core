#include "psa_init.h"

static int inited = 0;

int psa_crypto_init_once(void)
{
	if (inited == 1) {
		return PSA_SUCCESS;
	}

	psa_status_t st = psa_crypto_init();
	inited = 1;

	return st;
}