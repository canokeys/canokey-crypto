#ifndef CANOKEY_CRYPTO_AES_H
#define CANOKEY_CRYPTO_AES_H

#include <crypto-define.h>

CRYPTO_RESULT aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
CRYPTO_RESULT aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
