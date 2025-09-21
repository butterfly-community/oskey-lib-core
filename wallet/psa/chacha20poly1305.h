#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include "option.h"

int32_t psa_chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
				     const uint8_t *plaintext, size_t plaintext_len,
				     uint8_t *ciphertext, size_t ciphertext_size,
				     size_t *ciphertext_len);

int32_t psa_chacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
				     const uint8_t *ciphertext, size_t ciphertext_len,
				     uint8_t *plaintext, size_t plaintext_size,
				     size_t *plaintext_len);

#endif