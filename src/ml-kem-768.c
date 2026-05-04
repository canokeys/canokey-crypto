// SPDX-License-Identifier: Apache-2.0
#include <ml-kem-768.h>

#ifdef USE_MBEDCRYPTO
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
#ifdef USE_MBEDCRYPTO
  uint8_t local_seed[MLKEM768_KEYGEN_SEED_BYTES];
  int ret;

  if (ek == NULL || dk == NULL) return -1;
  if (seed == NULL) {
    random_buffer(local_seed, sizeof(local_seed));
    seed = local_seed;
  }

  ret = canokey_crypto_mlkem768_keypair_derand(ek, dk, seed);
  mbedtls_platform_zeroize(local_seed, sizeof(local_seed));
  return ret;
#else
  (void)ek;
  (void)dk;
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
