/*
 * SHA-3 / Keccak / SHAKE interface for canokey-crypto.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SHA3_H__
#define __SHA3_H__

#include <stddef.h>
#include <stdint.h>

/* Digest sizes (bytes) */
#define sha3_224_hash_size 28
#define sha3_256_hash_size 32
#define sha3_384_hash_size 48
#define sha3_512_hash_size 64
#define sha3_max_permutation_size 25

/* Block sizes = rate in bytes */
#define SHA3_224_BLOCK_LENGTH 144
#define SHA3_256_BLOCK_LENGTH 136
#define SHA3_384_BLOCK_LENGTH 104
#define SHA3_512_BLOCK_LENGTH 72
#define SHAKE128_BLOCK_LENGTH 168
#define SHAKE256_BLOCK_LENGTH 136

/* Digest length aliases */
#define SHA3_224_DIGEST_LENGTH sha3_224_hash_size
#define SHA3_256_DIGEST_LENGTH sha3_256_hash_size
#define SHA3_384_DIGEST_LENGTH sha3_384_hash_size
#define SHA3_512_DIGEST_LENGTH sha3_512_hash_size

/**
 * Unified Keccak sponge context.
 * Used for SHA-3, Keccak, and SHAKE.
 */
typedef struct SHA3_CTX {
  uint64_t hash[sha3_max_permutation_size]; /* 1600-bit state */
  unsigned rest;                            /* absorb index + flags */
  unsigned block_size;                      /* rate in bytes */
} SHA3_CTX;

/* ----- Init ----- */
void sha3_224_Init(SHA3_CTX *ctx);
void sha3_256_Init(SHA3_CTX *ctx);
void sha3_384_Init(SHA3_CTX *ctx);
void sha3_512_Init(SHA3_CTX *ctx);
void shake128_Init(SHA3_CTX *ctx);
void shake256_Init(SHA3_CTX *ctx);

/* ----- Update (shared across all modes) ----- */
void keccak_Update(SHA3_CTX *ctx, const unsigned char *msg, size_t size);

/* All modes share the same absorb function */
#define sha3_Update keccak_Update
#define shake_Update keccak_Update

/* ----- Finalize (fixed-length digest) ----- */
void sha3_Finalize(SHA3_CTX *ctx, unsigned char *result);   /* pad 0x06 */
void keccak_Finalize(SHA3_CTX *ctx, unsigned char *result); /* pad 0x01 */

/* ----- SHAKE XOF ----- */
void shake_Finalize(SHA3_CTX *ctx);
void shake_Squeeze(SHA3_CTX *ctx, unsigned char *out, size_t out_len);

/* ----- One-shot convenience ----- */
void sha3_256(const unsigned char *data, size_t len, unsigned char *digest);
void sha3_512(const unsigned char *data, size_t len, unsigned char *digest);
void keccak_256(const unsigned char *data, size_t len, unsigned char *digest);
void keccak_512(const unsigned char *data, size_t len, unsigned char *digest);
void shake128(const unsigned char *data, size_t len, unsigned char *out, size_t out_len);
void shake256(const unsigned char *data, size_t len, unsigned char *out, size_t out_len);

/* ----- Keccak Init aliases (same rate as SHA-3, different padding at finalize) ----- */
#define keccak_224_Init sha3_224_Init
#define keccak_256_Init sha3_256_Init
#define keccak_384_Init sha3_384_Init
#define keccak_512_Init sha3_512_Init

/* ----- Backward compatibility ----- */
#define sha3_Final sha3_Finalize
#define keccak_Final keccak_Finalize

#endif /* __SHA3_H__ */
