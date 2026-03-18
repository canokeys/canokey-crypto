/*
 * SHA-3 / Keccak / SHAKE interface for canokey-crypto.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage example:
 *
 *   // SHA3-256 one-shot
 *   uint8_t digest[SHA3_256_DIGEST_LENGTH];
 *   sha3_256_raw(data, data_len, digest);
 *
 *   // SHA3-256 incremental
 *   SHA3_CTX_T ctx; // the context type could be defined by user
 *   sha3_256_init(&ctx);
 *   sha3_update(&ctx, part1, len1);
 *   sha3_update(&ctx, part2, len2);
 *   sha3_finalize(&ctx, digest);
 *
 *   // SHAKE256 XOF
 *   SHA3_CTX_T ctx;
 *   shake256_init(&ctx);
 *   shake_update(&ctx, data, len);
 *   shake_finalize(&ctx);
 *   shake_squeeze(&ctx, out1, 32);
 *   shake_squeeze(&ctx, out2, 64);  // continue squeezing
 */

#ifndef __SHA3_H__
#define __SHA3_H__

#include <stddef.h>
#include <stdint.h>

/* Block sizes = rate in bytes */
#define SHA3_224_BLOCK_LENGTH 144
#define SHA3_256_BLOCK_LENGTH 136
#define SHA3_384_BLOCK_LENGTH 104
#define SHA3_512_BLOCK_LENGTH 72
#define SHAKE128_BLOCK_LENGTH 168
#define SHAKE256_BLOCK_LENGTH 136

/* Digest sizes (bytes) */
enum {
  SHA3_224_DIGEST_LENGTH = 28,
  SHA3_256_DIGEST_LENGTH = 32,
  SHA3_384_DIGEST_LENGTH = 48,
  SHA3_512_DIGEST_LENGTH = 64,
};

/* Keccak state size */
#define SHA3_STATE_WORDS 25

/*
 * Default sponge context used by implementations in sha3.c.
 *
 * To use a custom context type, define SHA3_CTX_T before including this header.
 */
typedef struct {
  uint64_t hash[SHA3_STATE_WORDS]; /* 1600-bit state */
  unsigned rest;                   /* absorb index + flags */
  unsigned block_size;             /* rate in bytes */
} sha3_ctx_t;

#ifndef SHA3_CTX_T
#define SHA3_CTX_T sha3_ctx_t
#endif

/* ----- Provide the following strong symbols to override default implementation ---- */

/* ----- Init ----- */
void sha3_224_init(SHA3_CTX_T *ctx);
void sha3_256_init(SHA3_CTX_T *ctx);
void sha3_384_init(SHA3_CTX_T *ctx);
void sha3_512_init(SHA3_CTX_T *ctx);
void shake128_init(SHA3_CTX_T *ctx);
void shake256_init(SHA3_CTX_T *ctx);

/* ----- Update (shared across all modes) ----- */
void keccak_update(SHA3_CTX_T *ctx, const uint8_t *msg, size_t size);
#define sha3_update keccak_update
#define shake_update keccak_update

/* ----- Finalize (fixed-length digest) ----- */
void sha3_finalize(SHA3_CTX_T *ctx, uint8_t *result);   /* pad 0x06 */
void keccak_finalize(SHA3_CTX_T *ctx, uint8_t *result); /* pad 0x01 */

/* ----- SHAKE XOF ----- */
void shake_finalize(SHA3_CTX_T *ctx);
void shake_squeeze(SHA3_CTX_T *ctx, uint8_t *out, size_t out_len);

/* ----- One-shot convenience (allocate context on stack) ----- */
void sha3_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]);
void sha3_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]);
void keccak_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]);
void keccak_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]);
void shake128_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);
void shake256_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);

/* ----- Keccak Init aliases (same rate, different padding at finalize) ----- */
#define keccak_224_init sha3_224_init
#define keccak_256_init sha3_256_init
#define keccak_384_init sha3_384_init
#define keccak_512_init sha3_512_init

#endif /* __SHA3_H__ */
