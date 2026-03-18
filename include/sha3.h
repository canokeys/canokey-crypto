/*
 * SHA-3 / Keccak / SHAKE interface for canokey-crypto.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __SHA3_H__
#define __SHA3_H__

#include <stddef.h>
#include <stdint.h>

/* Block sizes = rate in bytes */
#define SHA3_224_BLOCK_LENGTH 144
#define SHA3_256_BLOCK_LENGTH 136
#define SHA3_384_BLOCK_LENGTH 104
#define SHA3_512_BLOCK_LENGTH  72
#define SHAKE128_BLOCK_LENGTH 168
#define SHAKE256_BLOCK_LENGTH 136

/* Digest sizes (bytes) */
enum {
    SHA3_224_DIGEST_LENGTH = 28,
    SHA3_256_DIGEST_LENGTH = 32,
    SHA3_384_DIGEST_LENGTH = 48,
    SHA3_512_DIGEST_LENGTH = 64,
};

/* ----- Init ----- */
void sha3_224_init(void);
void sha3_256_init(void);
void sha3_384_init(void);
void sha3_512_init(void);
void shake128_init(void);
void shake256_init(void);

/* ----- Update (shared across all modes) ----- */
void keccak_update(const uint8_t *msg, size_t size);
#define sha3_update   keccak_update
#define shake_update  keccak_update

/* ----- Finalize (fixed-length digest) ----- */
void sha3_finalize(uint8_t *result);    /* pad 0x06 */
void keccak_finalize(uint8_t *result);  /* pad 0x01 */

/* ----- SHAKE XOF ----- */
void shake_finalize(void);
void shake_squeeze(uint8_t *out, size_t out_len);

/* ----- One-shot convenience ----- */
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
