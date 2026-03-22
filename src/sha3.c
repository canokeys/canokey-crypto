/*
 * SHA-3 / Keccak / SHAKE implementation based on FIPS 202.
 *
 * The sponge state (ctx->hash) is stored in XKCP's inplace-32bi
 * (bit-interleaved) format throughout the entire sponge lifecycle.
 * All absorb / pad / squeeze operations use the XKCP SnP assembly
 * interface directly, avoiding per-permutation format conversions.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef SHA3_CTX_T
#warning                                                                                                               \
    "SHA3_CTX_T is defined by user. You should override the symbols in sha3.c, or they WILL BREAK if SHA3_CTX_T has smaller size than sha3_ctx_t in <sha3.h>."
#endif

#include <memzero.h>
#include <sha3.h>
#include <string.h>

/* ---------- XKCP SnP interface (provided by keccak_f1600_armv6m.s) ---------- */

extern void KeccakP1600_Initialize(void *state);
extern void KeccakP1600_AddByte(void *state, unsigned char byte, unsigned int offset);
extern void KeccakP1600_AddBytes(void *state, const unsigned char *data,
                                 unsigned int offset, unsigned int length);
extern void KeccakP1600_ExtractBytes(void *state, unsigned char *data,
                                     unsigned int offset, unsigned int length);
extern void KeccakP1600_Permute_24rounds(void *state);

/*
 * ctx->hash is now used as a 200-byte XKCP inplace-32bi internal state,
 * NOT as a plain uint64_t[25] lane array.  Do not access it as uint64_t lanes.
 */
static inline void *keccak_state(sha3_ctx_t *ctx) {
  return (void *)ctx->hash;
}

/* ---------- Internal sponge operations ---------- */

#define SPONGE_FINALIZED 0x80000000u
#define SPONGE_SQUEEZED 0x40000000u
#define SPONGE_INDEX_MASK 0x0000FFFFu

static void keccak_absorb(sha3_ctx_t *ctx, const uint8_t *data, size_t len) {
  /* Reject absorption if context is uninitialized or sponge is finalized/squeezing */
  if (ctx->block_size == 0 ||
      (ctx->rest & (SPONGE_FINALIZED | SPONGE_SQUEEZED)) != 0) {
    return;
  }

  unsigned idx = ctx->rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx->block_size;
  void *state = keccak_state(ctx);

  while (len > 0) {
    unsigned todo = rate - idx;
    if (todo > len) todo = (unsigned)len;

    KeccakP1600_AddBytes(state, data, idx, todo);

    idx += todo;
    data += todo;
    len -= todo;

    if (idx == rate) {
      KeccakP1600_Permute_24rounds(state);
      idx = 0;
    }
  }
  /* Preserve state flags while updating the absorb index */
  ctx->rest = (ctx->rest & ~SPONGE_INDEX_MASK) | idx;
}

static void keccak_pad(sha3_ctx_t *ctx, uint8_t pad_byte) {
  unsigned idx = ctx->rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx->block_size;
  void *state = keccak_state(ctx);

  KeccakP1600_AddByte(state, pad_byte, idx);
  KeccakP1600_AddByte(state, 0x80, rate - 1);
  KeccakP1600_Permute_24rounds(state);

  ctx->rest = SPONGE_FINALIZED;
}

static void keccak_squeeze_internal(sha3_ctx_t *ctx, uint8_t *out, size_t out_len) {
  const unsigned rate = ctx->block_size;
  unsigned pos = (ctx->rest & SPONGE_SQUEEZED) ? (ctx->rest & SPONGE_INDEX_MASK) : 0;
  void *state = keccak_state(ctx);

  while (out_len > 0) {
    if (pos == rate) {
      KeccakP1600_Permute_24rounds(state);
      pos = 0;
    }
    unsigned avail = rate - pos;
    unsigned todo = (out_len < avail) ? (unsigned)out_len : avail;

    KeccakP1600_ExtractBytes(state, out, pos, todo);

    pos += todo;
    out += todo;
    out_len -= todo;
  }
  ctx->rest = SPONGE_FINALIZED | SPONGE_SQUEEZED | pos;
}

static void keccak_finalize_hash(sha3_ctx_t *ctx, uint8_t pad_byte, uint8_t *result) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, pad_byte);
  unsigned digest_len = (200 - ctx->block_size) / 2;
  keccak_squeeze_internal(ctx, result, digest_len);
  memzero(ctx, sizeof(sha3_ctx_t));
}

/* ---------- Init ---------- */

static void sponge_init(sha3_ctx_t *ctx, unsigned block_size) {
  memzero(ctx, sizeof(sha3_ctx_t));
  KeccakP1600_Initialize(keccak_state(ctx));
  ctx->block_size = block_size;
}

__attribute__((weak)) void sha3_224_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHA3_224_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_256_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHA3_256_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_384_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHA3_384_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_512_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHA3_512_BLOCK_LENGTH); }
__attribute__((weak)) void shake128_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHAKE128_BLOCK_LENGTH); }
__attribute__((weak)) void shake256_init(sha3_ctx_t *ctx) { sponge_init(ctx, SHAKE256_BLOCK_LENGTH); }

/* ---------- Update ---------- */

__attribute__((weak)) void keccak_update(sha3_ctx_t *ctx, const uint8_t *msg, size_t size) {
  keccak_absorb(ctx, msg, size);
}

/* ---------- Finalize ---------- */

__attribute__((weak)) void sha3_finalize(sha3_ctx_t *ctx, uint8_t *result) { keccak_finalize_hash(ctx, 0x06, result); }

__attribute__((weak)) void keccak_finalize(sha3_ctx_t *ctx, uint8_t *result) {
  keccak_finalize_hash(ctx, 0x01, result);
}

__attribute__((weak)) void shake_finalize(sha3_ctx_t *ctx) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, 0x1F);
}

/* ---------- Squeeze ---------- */

__attribute__((weak)) void shake_squeeze(sha3_ctx_t *ctx, uint8_t *out, size_t out_len) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, 0x1F);
  keccak_squeeze_internal(ctx, out, out_len);
}

/* ---------- One-shot convenience (context on stack) ---------- */

__attribute__((weak)) void keccak_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]) {
  sha3_ctx_t ctx;
  keccak_256_init(&ctx);
  keccak_update(&ctx, data, len);
  keccak_finalize(&ctx, digest);
}

__attribute__((weak)) void keccak_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]) {
  sha3_ctx_t ctx;
  keccak_512_init(&ctx);
  keccak_update(&ctx, data, len);
  keccak_finalize(&ctx, digest);
}

__attribute__((weak)) void sha3_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]) {
  sha3_ctx_t ctx;
  sha3_256_init(&ctx);
  sha3_update(&ctx, data, len);
  sha3_finalize(&ctx, digest);
}

__attribute__((weak)) void sha3_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]) {
  sha3_ctx_t ctx;
  sha3_512_init(&ctx);
  sha3_update(&ctx, data, len);
  sha3_finalize(&ctx, digest);
}

__attribute__((weak)) void shake128_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
  sha3_ctx_t ctx;
  shake128_init(&ctx);
  shake_update(&ctx, data, len);
  shake_finalize(&ctx);
  shake_squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(ctx));
}

__attribute__((weak)) void shake256_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
  sha3_ctx_t ctx;
  shake256_init(&ctx);
  shake_update(&ctx, data, len);
  shake_finalize(&ctx);
  shake_squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(ctx));
}
