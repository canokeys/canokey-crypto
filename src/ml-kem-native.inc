// SPDX-License-Identifier: Apache-2.0
#include MLKEM_HEADER

#ifdef USE_MBEDCRYPTO
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <rand.h>

#define MLK_CONFIG_CUSTOM_ZEROIZE
#define mlk_zeroize mbedtls_platform_zeroize
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_NAMESPACE_PREFIX MLKEM_NATIVE_PREFIX
#define MLK_CONFIG_PARAMETER_SET MLKEM_PARAMETER_SET
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
/* Keep API declarations before the amalgamated implementation. */
#include "mlkem_native.c"

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#endif

__attribute__((weak)) int MLKEM_API(keygen)(uint8_t *ek, uint8_t *dk, const uint8_t seed[MLKEM_KEYGEN_SEED_BYTES]) {
  if (ek == NULL) return -1;
  return MLKEM_API(keygen_optional_pk)(ek, dk, seed);
}

__attribute__((weak)) int MLKEM_API(keygen_optional_pk)(uint8_t *ek, uint8_t *dk,
                                                        const uint8_t seed[MLKEM_KEYGEN_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t *ek_buf = ek;
  uint8_t local_seed[MLKEM_KEYGEN_SEED_BYTES];
  int ret;

  if (dk == NULL) return -1;
  if (ek_buf == NULL) {
    ek_buf = mbedtls_calloc(1, MLKEM_PUBLIC_KEY_BYTES);
    if (ek_buf == NULL) return -1;
  }
  if (seed == NULL) {
    random_buffer(local_seed, sizeof(local_seed));
    seed = local_seed;
  }

  ret = MLKEM_NATIVE(keypair_derand)(ek_buf, dk, seed);
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

__attribute__((weak)) int
MLKEM_API(keygen_to_source)(uint8_t *ek, int (*write_dk)(void *ctx, size_t offset, const uint8_t *buf, size_t len),
                            void *dk_ctx, const uint8_t seed[MLKEM_KEYGEN_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  int ret;
  uint8_t *dk;

  if (write_dk == NULL) return -1;

  dk = mbedtls_calloc(1, MLKEM_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;

  ret = MLKEM_API(keygen_optional_pk)(ek, dk, seed);
  for (size_t offset = 0; ret == 0 && offset < MLKEM_SECRET_KEY_BYTES;) {
    const size_t remaining = MLKEM_SECRET_KEY_BYTES - offset;
    const size_t len = remaining < 384 ? remaining : 384;
    if (write_dk(dk_ctx, offset, dk + offset, len) != (int)len) ret = -1;
    offset += len;
  }

  mbedtls_platform_zeroize(dk, MLKEM_SECRET_KEY_BYTES);
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

__attribute__((weak)) int MLKEM_API(encaps)(uint8_t *ct, uint8_t ss[MLKEM_SHARED_KEY_BYTES], const uint8_t *ek,
                                            const uint8_t coins[MLKEM_ENCAPS_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t local_coins[MLKEM_ENCAPS_SEED_BYTES];
  int ret;

  if (ct == NULL || ss == NULL || ek == NULL) return -1;
  if (coins == NULL) {
    random_buffer(local_coins, sizeof(local_coins));
    coins = local_coins;
  }

  ret = MLKEM_NATIVE(enc_derand)(ct, ss, ek, coins);
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

__attribute__((weak)) int MLKEM_API(decaps)(uint8_t ss[MLKEM_SHARED_KEY_BYTES], const uint8_t *ct, const uint8_t *dk) {
#ifdef USE_MBEDCRYPTO
  if (ss == NULL || ct == NULL || dk == NULL) return -1;
  return MLKEM_NATIVE(dec)(ss, ct, dk);
#else
  (void)ss;
  (void)ct;
  (void)dk;
  return -1;
#endif
}

__attribute__((weak)) int MLKEM_API(seed_to_public)(uint8_t ek[MLKEM_PUBLIC_KEY_BYTES],
                                                    const uint8_t seed[MLKEM_KEYGEN_SEED_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t *dk;
  int ret;

  if (ek == NULL || seed == NULL) return -1;
  dk = mbedtls_calloc(1, MLKEM_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;
  ret = MLKEM_API(keygen_optional_pk)(ek, dk, seed);
  mbedtls_platform_zeroize(dk, MLKEM_SECRET_KEY_BYTES);
  mbedtls_free(dk);
  return ret == 0 ? 0 : -1;
#else
  (void)ek;
  (void)seed;
  return -1;
#endif
}

__attribute__((weak)) int MLKEM_API(decaps_seed)(uint8_t ss[MLKEM_SHARED_KEY_BYTES],
                                                 const uint8_t ct[MLKEM_CIPHERTEXT_BYTES],
                                                 const uint8_t seed[MLKEM_KEYGEN_SEED_BYTES],
                                                 uint8_t ek_scratch[MLKEM_PUBLIC_KEY_BYTES]) {
#ifdef USE_MBEDCRYPTO
  uint8_t *dk;
  int ret;

  if (ss == NULL || ct == NULL || seed == NULL || ek_scratch == NULL) return -1;
  dk = mbedtls_calloc(1, MLKEM_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;
  ret = MLKEM_API(keygen_optional_pk)(ek_scratch, dk, seed);
  if (ret == 0) ret = MLKEM_API(decaps)(ss, ct, dk);
  mbedtls_platform_zeroize(dk, MLKEM_SECRET_KEY_BYTES);
  mbedtls_free(dk);
  return ret == 0 ? 0 : -1;
#else
  (void)ss;
  (void)ct;
  (void)seed;
  (void)ek_scratch;
  return -1;
#endif
}

__attribute__((weak)) int
MLKEM_API(decaps_key_from_source)(uint8_t ss[MLKEM_SHARED_KEY_BYTES], const uint8_t ct[MLKEM_CIPHERTEXT_BYTES],
                                  int (*read_dk)(void *ctx, size_t offset, uint8_t *buf, size_t len), void *dk_ctx) {
#ifdef USE_MBEDCRYPTO
  int ret;
  uint8_t *dk;

  if (ss == NULL || ct == NULL || read_dk == NULL) return -1;

  dk = mbedtls_calloc(1, MLKEM_SECRET_KEY_BYTES);
  if (dk == NULL) return -1;
  ret = read_dk(dk_ctx, 0, dk, MLKEM_SECRET_KEY_BYTES);
  if (ret == (int)MLKEM_SECRET_KEY_BYTES) {
    ret = MLKEM_API(decaps)(ss, ct, dk);
  } else {
    ret = -1;
  }
  mbedtls_platform_zeroize(dk, MLKEM_SECRET_KEY_BYTES);
  mbedtls_free(dk);
  return ret == 0 ? 0 : -1;
#else
  (void)ss;
  (void)ct;
  (void)read_dk;
  (void)dk_ctx;
  return -1;
#endif
}
