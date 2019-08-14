#ifndef CANOKEY_CRYPTO_AES_H
#define CANOKEY_CRYPTO_AES_H

void aes128_enc(const void *in, void *out, const void *key);
void aes128_dec(const void *in, void *out, const void *key);

#endif
