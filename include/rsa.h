#ifndef CANOKEY_CRYPTO_RSA_H_
#define CANOKEY_CRYPTO_RSA_H_

#include <stddef.h>
#include <stdint.h>

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
int rsa_private(rsa_key_t *key, const uint8_t *input, uint8_t *output);
int rsa_sign_pkcs_v15(rsa_key_t *key, const uint8_t *data, uint16_t len,
                      uint8_t *sig);
int rsa_decrypt_pkcs_v15(rsa_key_t *key, const uint8_t *in, uint16_t *olen,
                         uint8_t *out);

#endif
