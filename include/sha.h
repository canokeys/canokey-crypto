/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SHA_H_
#define CANOKEY_CRYPTO_SHA_H_

#include <stddef.h>
#include <stdint.h>

#ifdef USE_MBEDCRYPTO
#include <psa/crypto.h>
#endif

#define SHA1_BLOCK_LENGTH 64
#define SHA1_DIGEST_LENGTH 20
#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64

#ifdef USE_MBEDCRYPTO
typedef struct {
  psa_hash_operation_t op;
} sha1_ctx_t;

typedef struct {
  psa_hash_operation_t op;
} sha256_ctx_t;

typedef struct {
  psa_hash_operation_t op;
} sha512_ctx_t;
#else
typedef struct {
  unsigned int digest_buf[SHA1_DIGEST_LENGTH / sizeof(unsigned int)];
  uint8_t block_buf[SHA1_BLOCK_LENGTH];
  uint8_t block_buf_size;
} sha1_ctx_t;

typedef struct {
  unsigned int digest_buf[SHA256_DIGEST_LENGTH / sizeof(unsigned int)];
  uint8_t block_buf[SHA256_BLOCK_LENGTH];
  uint8_t block_buf_size;
} sha256_ctx_t;

typedef struct {
  unsigned int digest_buf[SHA512_DIGEST_LENGTH / sizeof(unsigned int)];
  uint8_t block_buf[SHA512_BLOCK_LENGTH];
  uint8_t block_buf_size;
} sha512_ctx_t;
#endif

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]);
void sha1_raw(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]);
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]);
void sha256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);
void sha512_init(sha512_ctx_t *ctx);
void sha512_update(sha512_ctx_t *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx_t *ctx, uint8_t digest[SHA512_DIGEST_LENGTH]);
void sha512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]);

#endif
