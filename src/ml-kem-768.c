// SPDX-License-Identifier: Apache-2.0
#include <ml-kem-768.h>

#ifdef USE_MBEDCRYPTO
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <rand.h>

#define MLK_CONFIG_CUSTOM_ZEROIZE
#define mlk_zeroize mbedtls_platform_zeroize
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_NAMESPACE_PREFIX canokey_crypto_mlkem768
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_SUPERCOP

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include "mlkem_native.h"
#include "mlkem_native.c"

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#endif

__attribute__((weak)) int ml_kem_768_keygen(uint8_t *ek, uint8_t *dk,
                                            const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]) {
  if (ek == NULL) return -1;
  return ml_kem_768_keygen_optional_pk(ek, dk, seed);
}

__attribute__((weak)) int ml_kem_768_keygen_optional_pk(uint8_t *ek, uint8_t *dk,
                                                        const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t *ek_buf = ek;
  uint8_t local_seed[MLKEM768_KEYGEN_SEED_BYTES];
  int ret;

  if (dk == NULL) return -1;
  if (ek_buf == NULL) {
    ek_buf = mbedtls_calloc(1, MLKEM768_PUBLIC_KEY_BYTES);
    if (ek_buf == NULL) return -1;
  }
  if (seed == NULL) {
    random_buffer(local_seed, sizeof(local_seed));
    seed = local_seed;
  }

  ret = canokey_crypto_mlkem768_keypair_derand(ek_buf, dk, seed);
  mbedtls_platform_zeroize(local_seed, sizeof(local_seed));
  if (ek == NULL) mbedtls_free(ek_buf);
  return ret;
#else
  (void)ek;
  (void)dk;
  (void)seed;
  return -1;
#endif
}

__attribute__((weak)) int ml_kem_768_keygen_to_source(
    uint8_t *ek, int (*write_dk)(void *ctx, size_t offset, const uint8_t *buf, size_t len), void *dk_ctx,
    const uint8_t seed[MLKEM768_KEYGEN_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  int ret;
  uint8_t *dk;

  if (write_dk == NULL) return -1;

  dk = mbedtls_calloc(1, MLKEM768_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;

  ret = ml_kem_768_keygen_optional_pk(ek, dk, seed);
  if (ret == 0 && write_dk(dk_ctx, 0, dk, MLKEM768_SECRET_KEY_BYTES) != (int)MLKEM768_SECRET_KEY_BYTES) ret = -1;

  mbedtls_platform_zeroize(dk, MLKEM768_SECRET_KEY_BYTES);
  mbedtls_free(dk);
  return ret == 0 ? 0 : -1;
#else
  (void)ek;
  (void)write_dk;
  (void)dk_ctx;
  (void)seed;
  return -1;
#endif
}

__attribute__((weak)) int ml_kem_768_encaps(uint8_t *ct, uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ek,
                                            const uint8_t coins[MLKEM768_ENCAPS_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t local_coins[MLKEM768_ENCAPS_SEED_BYTES];
  int ret;

  if (ct == NULL || ss == NULL || ek == NULL) return -1;
  if (coins == NULL) {
    random_buffer(local_coins, sizeof(local_coins));
    coins = local_coins;
  }

  ret = canokey_crypto_mlkem768_enc_derand(ct, ss, ek, coins);
  mbedtls_platform_zeroize(local_coins, sizeof(local_coins));
  return ret;
#else
  (void)ct;
  (void)ss;
  (void)ek;
  (void)coins;
  return -1;
#endif
}

__attribute__((weak)) int ml_kem_768_decaps(uint8_t ss[MLKEM768_SHARED_KEY_BYTES], const uint8_t *ct,
                                            const uint8_t *dk) {
#ifdef USE_MBEDCRYPTO
  if (ss == NULL || ct == NULL || dk == NULL) return -1;
  return canokey_crypto_mlkem768_dec(ss, ct, dk);
#else
  (void)ss;
  (void)ct;
  (void)dk;
  return -1;
#endif
}

__attribute__((weak)) int ml_kem_768_decaps_from_source(
    uint8_t ss[MLKEM768_SHARED_KEY_BYTES], int (*read)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *ctx,
    const uint8_t *dk) {
#ifdef USE_MBEDCRYPTO
  int ret;
  uint8_t *ct;

  if (ss == NULL || read == NULL || dk == NULL) return -1;

  ct = mbedtls_calloc(1, MLKEM768_CIPHERTEXT_BYTES);
  if (ct == NULL) return -1;
  ret = read(ctx, 0, ct, MLKEM768_CIPHERTEXT_BYTES);
  if (ret == (int)MLKEM768_CIPHERTEXT_BYTES) {
    ret = ml_kem_768_decaps(ss, ct, dk);
  } else {
    ret = -1;
  }
  mbedtls_platform_zeroize(ct, MLKEM768_CIPHERTEXT_BYTES);
  mbedtls_free(ct);
  return ret == 0 ? 0 : -1;
#else
  (void)ss;
  (void)read;
  (void)ctx;
  (void)dk;
  return -1;
#endif
}

__attribute__((weak)) int ml_kem_768_decaps_key_from_source(
    uint8_t ss[MLKEM768_SHARED_KEY_BYTES], int (*read_ct)(void *ctx, size_t offset, uint8_t *buf, size_t len),
    void *ct_ctx, int (*read_dk)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *dk_ctx) {
#ifdef USE_MBEDCRYPTO
  int ret;
  uint8_t *dk;

  if (ss == NULL || read_ct == NULL || read_dk == NULL) return -1;

  dk = mbedtls_calloc(1, MLKEM768_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;
  ret = read_dk(dk_ctx, 0, dk, MLKEM768_SECRET_KEY_BYTES);
  if (ret == (int)MLKEM768_SECRET_KEY_BYTES) {
    ret = ml_kem_768_decaps_from_source(ss, read_ct, ct_ctx, dk);
  } else {
    ret = -1;
  }
  mbedtls_platform_zeroize(dk, MLKEM768_SECRET_KEY_BYTES);
  mbedtls_free(dk);
  return ret == 0 ? 0 : -1;
#else
  (void)ss;
  (void)read_ct;
  (void)ct_ctx;
  (void)read_dk;
  (void)dk_ctx;
  return -1;
#endif
}
