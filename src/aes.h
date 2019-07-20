#ifndef CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H
#define CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H

#include <stdint.h>

void aes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
void aes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif //CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H
