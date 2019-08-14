#ifndef CANOKEY_CRYPTO_RSA_H_
#define CANOKEY_CRYPTO_RSA_H_

#include <stdint.h>
#include <stddef.h>

#define RSA_N_BIT 2048u
#define E_LENGTH 4
#define N_LENGTH (RSA_N_BIT / 8)
#define PQ_LENGTH (RSA_N_BIT / 16)

typedef struct {
  uint8_t e[E_LENGTH];
  uint8_t p[PQ_LENGTH];
  uint8_t q[PQ_LENGTH];
  uint8_t n[N_LENGTH];
} rsa_key_t;

int rsa_generate_key(rsa_key_t *key);
int rsa_complete_key(rsa_key_t *key);
int rsa_private(rsa_key_t *key, const void *input, void *output);
int rsa_sign_pkcs_v15(rsa_key_t *key, const void *data, uint16_t len,
                      void *sig);
int rsa_decrypt_pkcs_v15(rsa_key_t *key, const void *in, size_t *olen,
                         void *out);

#endif
