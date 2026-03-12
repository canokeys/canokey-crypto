// SPDX-License-Identifier: Apache-2.0
#include <sha.h>
#include <stdint.h>

#ifdef USE_MBEDCRYPTO
#include <psa/crypto.h>

#define PSA_CHECK(call)                                                                                                \
  do {                                                                                                                 \
    if ((call) != PSA_SUCCESS) return;                                                                                 \
  } while (0)

static psa_hash_operation_t sha1_op = PSA_HASH_OPERATION_INIT;
static psa_hash_operation_t sha256_op = PSA_HASH_OPERATION_INIT;
static psa_hash_operation_t sha512_op = PSA_HASH_OPERATION_INIT;
#endif

__attribute__((weak)) void sha1_init() {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  sha1_op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&sha1_op, PSA_ALG_SHA_1));
#endif
}

__attribute__((weak)) void sha1_update(const uint8_t *data, uint16_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&sha1_op, data, len));
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&sha1_op, digest, SHA1_DIGEST_LENGTH, &hash_len));
#else
  (void)digest;
#endif
}

void sha1_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_init();
  sha1_update(data, len);
  sha1_final(digest);
}

__attribute__((weak)) void sha256_init() {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  sha256_op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&sha256_op, PSA_ALG_SHA_256));
#endif
}

__attribute__((weak)) void sha256_update(const uint8_t *data, uint16_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&sha256_op, data, len));
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&sha256_op, digest, SHA256_DIGEST_LENGTH, &hash_len));
#else
  (void)digest;
#endif
}

void sha256_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_init();
  sha256_update(data, len);
  sha256_final(digest);
}

__attribute__((weak)) void sha512_init() {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  sha512_op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&sha512_op, PSA_ALG_SHA_512));
#endif
}

__attribute__((weak)) void sha512_update(const uint8_t *data, uint16_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&sha512_op, data, len));
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&sha512_op, digest, SHA512_DIGEST_LENGTH, &hash_len));
#else
  (void)digest;
#endif
}

void sha512_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_init();
  sha512_update(data, len);
  sha512_final(digest);
}
