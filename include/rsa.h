#ifndef CANOKEY_CORE_CANOKEY_CRYPTO_INCLUDE_RSA_H_
#define CANOKEY_CORE_CANOKEY_CRYPTO_INCLUDE_RSA_H_

#include <stdint.h>

typedef struct {
  uint16_t nbits;
  uint8_t e[4];
  uint8_t p[128];
  uint8_t q[128];
  uint8_t n[256];
} rsa_key_t;

int rsa_generate_key(rsa_key_t *key, uint16_t nbits);
int rsa_sign_pkcs_v15(rsa_key_t *key, const void *data, uint16_t len,
                      void *sig);

#endif // CANOKEY_CORE_CANOKEY_CRYPTO_INCLUDE_RSA_H_
