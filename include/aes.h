#ifndef CANOKEY_CRYPTO_AES_H
#define CANOKEY_CRYPTO_AES_H

#include <stdint.h>

int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
