#ifndef CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H
#define CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H

void aes128_enc(const void *in, void *out, const void *key);
void aes128_dec(const void *in, void *out, const void *key);

#endif //CANOKEY_CORE_CANOKEY_CRYPTO_SRC_AES_H
