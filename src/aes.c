// SPDX-License-Identifier: Apache-2.0
#include <aes.h>
#ifdef USE_MBEDCRYPTO
#include <psa/crypto.h>

static void ensure_psa_init(void) {
  static int inited = 0;
  if (!inited) {
    psa_crypto_init();
    inited = 1;
  }
}

static int aes_ecb(const void *in, void *out, const void *key, size_t keybits, psa_key_usage_t usage) {
  ensure_psa_init();
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, keybits);
  psa_set_key_usage_flags(&attr, usage);
  psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);

  psa_key_id_t key_id;
  if (psa_import_key(&attr, key, keybits / 8, &key_id) != PSA_SUCCESS) return -1;

  size_t out_len;
  psa_status_t status;
  if (usage == PSA_KEY_USAGE_ENCRYPT)
    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &out_len);
  else
    status = psa_cipher_decrypt(key_id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &out_len);

  psa_destroy_key(key_id);
  return status == PSA_SUCCESS ? 0 : -1;
}
#endif

__attribute__((weak)) int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 128, PSA_KEY_USAGE_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 128, PSA_KEY_USAGE_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 256, PSA_KEY_USAGE_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 256, PSA_KEY_USAGE_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}
