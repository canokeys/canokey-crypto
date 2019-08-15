#ifndef CANOKEY_CRYPTO_DES_H_
#define CANOKEY_CRYPTO_DES_H_

#include <crypto-define.h>

CRYPTO_RESULT des_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
CRYPTO_RESULT des_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
CRYPTO_RESULT tdes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
CRYPTO_RESULT tdes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
