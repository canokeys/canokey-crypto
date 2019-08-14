#include <aes.h>
#ifdef USE_MBEDCRYPTO
#include <mbedtls/aes.h>

static void aes(const void *in, void *out, const void *key, int keybits,
                int mode) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  if (mode == MBEDTLS_AES_ENCRYPT)
    mbedtls_aes_setkey_enc(&aes, key, keybits);
  else
    mbedtls_aes_setkey_dec(&aes, key, keybits);
  mbedtls_aes_crypt_ecb(&aes, mode, in, out);
}
#endif

__attribute__((weak)) void aes128_enc(const void *in, void *out,
                                      const void *key) {
#ifdef USE_MBEDCRYPTO
  aes(in, out, key, 128, MBEDTLS_AES_ENCRYPT);
#else
  (void) in;
  (void) out;
  (void) key;
  return;
#endif
}

__attribute__((weak)) void aes128_dec(const void *in, void *out,
                                      const void *key) {
#ifdef USE_MBEDCRYPTO
  aes(in, out, key, 128, MBEDTLS_AES_DECRYPT);
#else
  (void) in;
  (void) out;
  (void) key;
  return;
#endif
}
