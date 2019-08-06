#ifndef CANOKEY_CORE_CANOKEY_CRYPTO_SRC_DES_H_
#define CANOKEY_CORE_CANOKEY_CRYPTO_SRC_DES_H_

void des_enc(const void *in, void *out, const void *key);
void des_dec(const void *in, void *out, const void *key);
void tdes_enc(const void *in, void *out, const void *key);
void tdes_dec(const void *in, void *out, const void *key);

#endif // CANOKEY_CORE_CANOKEY_CRYPTO_SRC_DES_H_
