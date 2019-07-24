#include <mbedtls/rsa.h>
#include <memory.h>
#include <rand.h>
#include <rsa.h>

static int rnd(void *ctx, unsigned char *buf, size_t n) {
  (void)ctx;
  random_buffer(buf, n);
  return 0;
}

__attribute__((weak)) int rsa_generate_key(rsa_key_t *key, uint16_t nbits) {
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  if (mbedtls_rsa_gen_key(&rsa, rnd, NULL, nbits, 65537) < 0)
    return -1;
  key->nbits = nbits;
  if (mbedtls_rsa_export_raw(&rsa, key->n, nbits / 8, key->p, nbits / 16,
                             key->q, nbits / 16, NULL, 0, key->e, 4) < 0)
    return -1;
  return 0;
}

__attribute__((weak)) int rsa_sign_pkcs_v15(rsa_key_t *key, const void *data,
                                            uint16_t len, void *sig) {
  mbedtls_rsa_context rsa;
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  if (mbedtls_rsa_import_raw(&rsa, key->n, key->nbits / 8, key->p,
                             key->nbits / 16, key->q, key->nbits / 16, NULL, 0,
                             key->e, 4) < 0)
    return -1;
  if (mbedtls_rsa_complete(&rsa) < 0)
    return -1;
  if (mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, rnd, NULL, MBEDTLS_RSA_PRIVATE,
                                        MBEDTLS_MD_NONE, len, data, sig) < 0)
    return -1;
  return 0;
}
