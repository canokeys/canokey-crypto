/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SM3_H_
#define CANOKEY_CRYPTO_SM3_H_

#include <stddef.h>
#include <stdint.h>

#define SM3_BLOCK_LENGTH 64
#define SM3_DIGEST_LENGTH 32

#ifdef USE_MBEDCRYPTO
typedef struct {
  uint32_t digest[SM3_DIGEST_LENGTH / sizeof(uint32_t)];
  uint32_t nblocks;
  uint8_t block[SM3_BLOCK_LENGTH];
  uint32_t num;
} sm3_ctx_t;
#else
// Hardware platforms may define SM3_STATE_WORDS to enlarge digest_buf[]
#ifndef SM3_CTX_DIGEST_WORDS
#ifdef SM3_STATE_WORDS
#define SM3_CTX_DIGEST_WORDS SM3_STATE_WORDS
#else
#define SM3_CTX_DIGEST_WORDS (SM3_DIGEST_LENGTH / sizeof(uint32_t))
#endif
#endif

typedef struct {
  unsigned int digest_buf[SM3_CTX_DIGEST_WORDS];
  uint8_t block_buf[SM3_BLOCK_LENGTH];
  uint8_t block_buf_size;
} sm3_ctx_t;
#endif

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_LENGTH]);
void sm3_raw(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_LENGTH]);

#endif
