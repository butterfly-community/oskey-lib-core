#ifndef PSA_SCALAR_H
#define PSA_SCALAR_H

#include "option.h"

static int psa_scalar_cmp(const uint8_t *a, const uint8_t *b)
{
	uint32_t greater = 0;
	uint32_t less = 0;

	for (size_t i = 0; i < 32; i++) {
		const uint32_t undecided = 1U ^ (greater | less);

		greater |= (((uint32_t)b[i] - a[i]) >> 31) & undecided;
		less |= (((uint32_t)a[i] - b[i]) >> 31) & undecided;
	}
	return (int)greater - (int)less;
}

static bool psa_scalar_is_zero(const uint8_t *value)
{
	uint8_t result = 0;

	for (size_t i = 0; i < 32; i++) {
		result |= value[i];
	}
	return result == 0;
}

static bool psa_scalar_is_valid(const uint8_t *value, const uint8_t *order)
{
	return !psa_scalar_is_zero(value) && psa_scalar_cmp(value, order) < 0;
}

static void psa_scalar_sub(uint8_t *value, const uint8_t *subtrahend)
{
	uint16_t borrow = 0;

	for (size_t i = 32; i > 0; i--) {
		const uint16_t minuend = value[i - 1];
		const uint16_t sub = (uint16_t)subtrahend[i - 1] + borrow;
		value[i - 1] = (uint8_t)(minuend - sub);
		borrow = minuend < sub;
	}
}

static int psa_scalar_add(const uint8_t *parent, const uint8_t *tweak, const uint8_t *order,
			  uint8_t *result)
{
	uint16_t carry = 0;

	if (!psa_scalar_is_valid(parent, order) || psa_scalar_cmp(tweak, order) >= 0) {
		return -1;
	}

	for (size_t i = 32; i > 0; i--) {
		const uint16_t sum = (uint16_t)parent[i - 1] + tweak[i - 1] + carry;
		result[i - 1] = (uint8_t)sum;
		carry = sum >> 8;
	}

	if (carry != 0 || psa_scalar_cmp(result, order) >= 0) {
		psa_scalar_sub(result, order);
	}

	return psa_scalar_is_zero(result) ? -1 : 0;
}

#endif
