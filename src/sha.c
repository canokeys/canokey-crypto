// SPDX-License-Identifier: Apache-2.0
#include <sha.h>
#include <memzero.h>
#include <stdint.h>

#ifdef USE_MBEDCRYPTO
#define PSA_CHECK(call)                                                                                                \
  do {                                                                                                                 \
    if ((call) != PSA_SUCCESS) return;                                                                                 \
  } while (0)
#endif

__attribute__((weak)) void sha1_init(sha1_ctx_t *ctx) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  ctx->op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&ctx->op, PSA_ALG_SHA_1));
#else
  (void)ctx;
#endif
}

__attribute__((weak)) void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&ctx->op, data, len));
#else
  (void)ctx;
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha1_final(sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&ctx->op, digest, SHA1_DIGEST_LENGTH, &hash_len));
  memzero(ctx, sizeof(*ctx));
#else
  (void)ctx;
  (void)digest;
#endif
}

void sha1_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]) {
  sha1_ctx_t ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, data, len);
  sha1_final(&ctx, digest);
}

__attribute__((weak)) void sha256_init(sha256_ctx_t *ctx) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  ctx->op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&ctx->op, PSA_ALG_SHA_256));
#else
  (void)ctx;
#endif
}

__attribute__((weak)) void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&ctx->op, data, len));
#else
  (void)ctx;
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&ctx->op, digest, SHA256_DIGEST_LENGTH, &hash_len));
  memzero(ctx, sizeof(*ctx));
#else
  (void)ctx;
  (void)digest;
#endif
}

void sha256_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

__attribute__((weak)) void sha512_init(sha512_ctx_t *ctx) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_crypto_init());
  ctx->op = psa_hash_operation_init();
  PSA_CHECK(psa_hash_setup(&ctx->op, PSA_ALG_SHA_512));
#else
  (void)ctx;
#endif
}

__attribute__((weak)) void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len) {
#ifdef USE_MBEDCRYPTO
  PSA_CHECK(psa_hash_update(&ctx->op, data, len));
#else
  (void)ctx;
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sha512_final(sha512_ctx_t *ctx, uint8_t digest[SHA512_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  size_t hash_len;
  PSA_CHECK(psa_hash_finish(&ctx->op, digest, SHA512_DIGEST_LENGTH, &hash_len));
  memzero(ctx, sizeof(*ctx));
#else
  (void)ctx;
  (void)digest;
#endif
}

void sha512_raw(const uint8_t *data, const size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
  sha512_ctx_t ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, data, len);
  sha512_final(&ctx, digest);
}
