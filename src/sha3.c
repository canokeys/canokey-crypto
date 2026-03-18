/*
 * SHA-3 / Keccak / SHAKE implementation based on FIPS 202.
 *
 * Keccak-f[1600] permutation derived from Mbed TLS (Apache-2.0 OR GPL-2.0-or-later),
 * using compressed round constants to minimize ROM usage.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memzero.h>
#include <sha3.h>
#include <string.h>

/* ---------- Internal context (single global instance) ---------- */

#define SHA3_MAX_PERMUTATION_SIZE 25

typedef struct {
  uint64_t hash[SHA3_MAX_PERMUTATION_SIZE]; /* 1600-bit state */
  unsigned rest;                            /* absorb index + flags */
  unsigned block_size;                      /* rate in bytes */
} sha3_ctx_t;

static sha3_ctx_t ctx;

/* ---------- Endianness helpers ---------- */

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define KECCAK_BIG_ENDIAN 1
#endif

#ifndef KECCAK_BIG_ENDIAN
#define KECCAK_BIG_ENDIAN 0
#endif

static inline void state_xor_byte(uint64_t *state, unsigned pos, uint8_t val) {
#if KECCAK_BIG_ENDIAN
  state[pos >> 3] ^= (uint64_t)val << ((pos & 7) * 8);
#else
  ((uint8_t *)state)[pos] ^= val;
#endif
}

static inline uint8_t state_get_byte(const uint64_t *state, unsigned pos) {
#if KECCAK_BIG_ENDIAN
  return (uint8_t)(state[pos >> 3] >> ((pos & 7) * 8));
#else
  return ((const uint8_t *)state)[pos];
#endif
}

/* ---------- Keccak-f[1600] permutation ---------- */

#define H(b63, b31, b15) ((b63) << 6 | (b31) << 5 | (b15) << 4)
static const uint8_t iota_r_packed[24] = {
    H(0, 0, 0) | 0x01, H(0, 0, 1) | 0x82, H(1, 0, 1) | 0x8a, H(1, 1, 1) | 0x00, H(0, 0, 1) | 0x8b, H(0, 1, 0) | 0x01,
    H(1, 1, 1) | 0x81, H(1, 0, 1) | 0x09, H(0, 0, 0) | 0x8a, H(0, 0, 0) | 0x88, H(0, 1, 1) | 0x09, H(0, 1, 0) | 0x0a,
    H(0, 1, 1) | 0x8b, H(1, 0, 0) | 0x8b, H(1, 0, 1) | 0x89, H(1, 0, 1) | 0x03, H(1, 0, 1) | 0x02, H(1, 0, 0) | 0x80,
    H(0, 0, 1) | 0x0a, H(1, 1, 0) | 0x0a, H(1, 1, 1) | 0x81, H(1, 0, 1) | 0x80, H(0, 1, 0) | 0x01, H(1, 1, 1) | 0x08,
};
#undef H

static const uint32_t rho[6] = {0x3f022425, 0x1c143a09, 0x2c3d3615, 0x27191713, 0x312b382e, 0x3e030832};

static const uint32_t pi[6] = {0x110b070a, 0x10050312, 0x04181508, 0x0d13170f, 0x0e14020c, 0x01060916};

#define ROTR64(x, y) (((x) << (64U - (y))) | ((x) >> (y)))
#define SWAP(x, y)                                                                                                     \
  do {                                                                                                                 \
    uint64_t tmp_ = (x);                                                                                               \
    (x) = (y);                                                                                                         \
    (y) = tmp_;                                                                                                        \
  } while (0)

static void keccak_f1600(uint64_t s[25]) {
  uint64_t lane[5];
  for (int round = 0; round < 24; round++) {
    uint64_t t;
    int i;

    /* Theta */
    for (i = 0; i < 5; i++)
      lane[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
    for (i = 0; i < 5; i++) {
      t = lane[(i + 4) % 5] ^ ROTR64(lane[(i + 1) % 5], 63);
      s[i] ^= t;
      s[i + 5] ^= t;
      s[i + 10] ^= t;
      s[i + 15] ^= t;
      s[i + 20] ^= t;
    }

    /* Rho */
    for (i = 1; i < 25; i += 4) {
      uint32_t r = rho[(i - 1) >> 2];
      for (int j = i; j < i + 4; j++) {
        s[j] = ROTR64(s[j], (uint8_t)(r >> 24));
        r <<= 8;
      }
    }

    /* Pi */
    t = s[1];
    for (i = 0; i < 24; i += 4) {
      uint32_t p = pi[i >> 2];
      for (unsigned j = 0; j < 4; j++) {
        SWAP(s[p & 0xff], t);
        p >>= 8;
      }
    }

    /* Chi */
    for (i = 0; i <= 20; i += 5) {
      lane[0] = s[i];
      lane[1] = s[i + 1];
      lane[2] = s[i + 2];
      lane[3] = s[i + 3];
      lane[4] = s[i + 4];
      s[i + 0] ^= (~lane[1]) & lane[2];
      s[i + 1] ^= (~lane[2]) & lane[3];
      s[i + 2] ^= (~lane[3]) & lane[4];
      s[i + 3] ^= (~lane[4]) & lane[0];
      s[i + 4] ^= (~lane[0]) & lane[1];
    }

    /* Iota */
    s[0] ^= ((iota_r_packed[round] & 0x40ull) << 57 | (iota_r_packed[round] & 0x20ull) << 26 |
             (iota_r_packed[round] & 0x10ull) << 11 | (iota_r_packed[round] & 0x8f));
  }
}

/* ---------- Internal sponge operations ---------- */

#define SPONGE_FINALIZED 0x80000000u
#define SPONGE_SQUEEZED 0x40000000u
#define SPONGE_INDEX_MASK 0x0000FFFFu

static void keccak_absorb(const uint8_t *data, size_t len) {
  /* Reject absorption if context is uninitialized or sponge is finalized/squeezing */
  if (ctx.block_size == 0 ||
      (ctx.rest & (SPONGE_FINALIZED | SPONGE_SQUEEZED)) != 0) {
    return;
  }

  unsigned idx = ctx.rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx.block_size;

  while (len > 0) {
    unsigned todo = rate - idx;
    if (todo > len) todo = (unsigned)len;

    for (unsigned i = 0; i < todo; i++)
      state_xor_byte(ctx.hash, idx + i, data[i]);

    idx += todo;
    data += todo;
    len -= todo;

    if (idx == rate) {
      keccak_f1600(ctx.hash);
      idx = 0;
    }
  }
  /* Preserve state flags while updating the absorb index */
  ctx.rest = (ctx.rest & ~SPONGE_INDEX_MASK) | idx;
}

static void keccak_pad(uint8_t pad_byte) {
  unsigned idx = ctx.rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx.block_size;

  state_xor_byte(ctx.hash, idx, pad_byte);
  state_xor_byte(ctx.hash, rate - 1, 0x80);
  keccak_f1600(ctx.hash);

  ctx.rest = SPONGE_FINALIZED;
}

static void keccak_squeeze_internal(uint8_t *out, size_t out_len) {
  const unsigned rate = ctx.block_size;
  unsigned pos = (ctx.rest & SPONGE_SQUEEZED) ? (ctx.rest & SPONGE_INDEX_MASK) : 0;

  while (out_len > 0) {
    if (pos == rate) {
      keccak_f1600(ctx.hash);
      pos = 0;
    }
    unsigned avail = rate - pos;
    unsigned todo = (out_len < avail) ? (unsigned)out_len : avail;

    for (unsigned i = 0; i < todo; i++)
      out[i] = state_get_byte(ctx.hash, pos + i);

    pos += todo;
    out += todo;
    out_len -= todo;
  }
  ctx.rest = SPONGE_FINALIZED | SPONGE_SQUEEZED | pos;
}

static void keccak_finalize_hash(uint8_t pad_byte, uint8_t *result) {
  if (!(ctx.rest & SPONGE_FINALIZED)) keccak_pad(pad_byte);
  unsigned digest_len = (200 - ctx.block_size) / 2;
  keccak_squeeze_internal(result, digest_len);
  memzero(&ctx, sizeof(ctx));
}

/* ---------- Init ---------- */

static void sponge_init(unsigned block_size) {
  memzero(&ctx, sizeof(ctx));
  ctx.block_size = block_size;
}

__attribute__((weak)) void sha3_224_init(void) { sponge_init(SHA3_224_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_256_init(void) { sponge_init(SHA3_256_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_384_init(void) { sponge_init(SHA3_384_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_512_init(void) { sponge_init(SHA3_512_BLOCK_LENGTH); }
__attribute__((weak)) void shake128_init(void) { sponge_init(SHAKE128_BLOCK_LENGTH); }
__attribute__((weak)) void shake256_init(void) { sponge_init(SHAKE256_BLOCK_LENGTH); }

/* ---------- Update ---------- */

__attribute__((weak)) void keccak_update(const uint8_t *msg, size_t size) { keccak_absorb(msg, size); }

/* ---------- Finalize ---------- */

__attribute__((weak)) void sha3_finalize(uint8_t *result) { keccak_finalize_hash(0x06, result); }

__attribute__((weak)) void keccak_finalize(uint8_t *result) { keccak_finalize_hash(0x01, result); }

__attribute__((weak)) void shake_finalize(void) {
  if (!(ctx.rest & SPONGE_FINALIZED)) keccak_pad(0x1F);
}

/* ---------- Squeeze ---------- */

__attribute__((weak)) void shake_squeeze(uint8_t *out, size_t out_len) {
  if (!(ctx.rest & SPONGE_FINALIZED)) keccak_pad(0x1F);
  keccak_squeeze_internal(out, out_len);
}

/* ---------- One-shot convenience ---------- */

__attribute__((weak)) void keccak_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]) {
  keccak_256_init();
  keccak_update(data, len);
  keccak_finalize(digest);
}

__attribute__((weak)) void keccak_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]) {
  keccak_512_init();
  keccak_update(data, len);
  keccak_finalize(digest);
}

__attribute__((weak)) void sha3_256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]) {
  sha3_256_init();
  sha3_update(data, len);
  sha3_finalize(digest);
}

__attribute__((weak)) void sha3_512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]) {
  sha3_512_init();
  sha3_update(data, len);
  sha3_finalize(digest);
}

__attribute__((weak)) void shake128_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
  shake128_init();
  shake_update(data, len);
  shake_finalize();
  shake_squeeze(out, out_len);
  memzero(&ctx, sizeof(ctx));
}

__attribute__((weak)) void shake256_raw(const uint8_t *data, size_t len, uint8_t *out, size_t out_len) {
  shake256_init();
  shake_update(data, len);
  shake_finalize();
  shake_squeeze(out, out_len);
  memzero(&ctx, sizeof(ctx));
}
