#ifndef CANOKEY_CRYPTO_DES_H_
#define CANOKEY_CRYPTO_DES_H_

#include <stdint.h>

int des_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int des_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
int tdes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int tdes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
