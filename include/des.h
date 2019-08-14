#ifndef CANOKEY_CRYPTO_DES_H_
#define CANOKEY_CRYPTO_DES_H_

void des_enc(const void *in, void *out, const void *key);
void des_dec(const void *in, void *out, const void *key);
void tdes_enc(const void *in, void *out, const void *key);
void tdes_dec(const void *in, void *out, const void *key);

#endif
