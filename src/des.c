#include <des.h>
#include <mbedtls/des.h>

__attribute__((weak)) void des_enc(const void *in, void *out, const void *key) {
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_enc(&ctx, key);
  mbedtls_des_crypt_ecb(&ctx, in, out);
  mbedtls_des_free(&ctx);
}

__attribute__((weak)) void des_dec(const void *in, void *out, const void *key) {
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_dec(&ctx, key);
  mbedtls_des_crypt_ecb(&ctx, in, out);
  mbedtls_des_free(&ctx);
}

__attribute__((weak)) void tdes_enc(const void *in, void *out,
                                    const void *key) {
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set3key_dec(&ctx, key);
  mbedtls_des3_crypt_ecb(&ctx, in, out);
  mbedtls_des3_free(&ctx);
}

__attribute__((weak)) void tdes_dec(const void *in, void *out,
                                    const void *key) {
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set3key_dec(&ctx, key);
  mbedtls_des3_crypt_ecb(&ctx, in, out);
  mbedtls_des3_free(&ctx);
}
