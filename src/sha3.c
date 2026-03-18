/*
 * SHA-3 / Keccak / SHAKE implementation based on FIPS 202.
 *
 * Keccak-f[1600] permutation derived from Mbed TLS (Apache-2.0 OR GPL-2.0-or-later),
 * using compressed round constants to minimize ROM usage.
 *
 * SHA-3, Keccak, and SHAKE wrappers written for canokey-crypto.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sha3.h"
#include <memzero.h>
#include <string.h>

/* ---------- Endianness helpers ---------- */

/*
 * Keccak state lanes are defined as little-endian uint64_t.
 * On big-endian platforms we must byte-swap when loading/storing.
 */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define KECCAK_BIG_ENDIAN 1
static inline uint64_t le64_load(const uint8_t *p) {
  uint64_t v;
  memcpy(&v, p, 8);
  return __builtin_bswap64(v);
}
static inline void le64_store(uint8_t *p, uint64_t v) {
  v = __builtin_bswap64(v);
  memcpy(p, &v, 8);
}
#else
#define KECCAK_BIG_ENDIAN 0
#endif

/* XOR byte into the sponge state at byte position pos (endian-safe) */
static inline void state_xor_byte(uint64_t *state, unsigned pos, uint8_t val) {
#if KECCAK_BIG_ENDIAN
  /* On big-endian, byte pos within a lane must be mirrored */
  unsigned lane = pos >> 3;
  unsigned byte_in_lane = pos & 7;
  state[lane] ^= (uint64_t)val << (byte_in_lane * 8);
#else
  ((uint8_t *)state)[pos] ^= val;
#endif
}

/* Read byte from sponge state at byte position pos (endian-safe) */
static inline uint8_t state_get_byte(const uint64_t *state, unsigned pos) {
#if KECCAK_BIG_ENDIAN
  unsigned lane = pos >> 3;
  unsigned byte_in_lane = pos & 7;
  return (uint8_t)(state[lane] >> (byte_in_lane * 8));
#else
  return ((const uint8_t *)state)[pos];
#endif
}

/* ---------- Keccak-f[1600] permutation (from Mbed TLS, size-optimized) ---------- */

/*
 * Compressed iota round constants. Only bits at positions 2^k-1 can be set
 * in each 64-bit mask. Bits 63, 31, 15 are packed into bits 6, 5, 4.
 */
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

static void keccak_absorb(SHA3_CTX *ctx, const uint8_t *data, size_t len) {
  unsigned idx = ctx->rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx->block_size;

  while (len > 0) {
    unsigned todo = rate - idx;
    if (todo > len) todo = (unsigned)len;

    for (unsigned i = 0; i < todo; i++)
      state_xor_byte(ctx->hash, idx + i, data[i]);

    idx += todo;
    data += todo;
    len -= todo;

    if (idx == rate) {
      keccak_f1600(ctx->hash);
      idx = 0;
    }
  }
  ctx->rest = idx;
}

static void keccak_pad(SHA3_CTX *ctx, uint8_t pad_byte) {
  unsigned idx = ctx->rest & SPONGE_INDEX_MASK;
  const unsigned rate = ctx->block_size;

  state_xor_byte(ctx->hash, idx, pad_byte);
  state_xor_byte(ctx->hash, rate - 1, 0x80);
  keccak_f1600(ctx->hash);

  ctx->rest = SPONGE_FINALIZED;
}

static void keccak_squeeze(SHA3_CTX *ctx, uint8_t *out, size_t out_len) {
  const unsigned rate = ctx->block_size;
  unsigned pos = (ctx->rest & SPONGE_SQUEEZED) ? (ctx->rest & SPONGE_INDEX_MASK) : 0;

  while (out_len > 0) {
    if (pos == rate) {
      keccak_f1600(ctx->hash);
      pos = 0;
    }
    unsigned avail = rate - pos;
    unsigned todo = (out_len < avail) ? (unsigned)out_len : avail;

    for (unsigned i = 0; i < todo; i++)
      out[i] = state_get_byte(ctx->hash, pos + i);

    pos += todo;
    out += todo;
    out_len -= todo;
  }
  ctx->rest = SPONGE_FINALIZED | SPONGE_SQUEEZED | pos;
}

/* Internal: finalize + extract fixed-length digest (for SHA-3 / Keccak) */
static void keccak_finalize_hash(SHA3_CTX *ctx, uint8_t pad_byte, unsigned char *result) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, pad_byte);
  unsigned digest_len = (200 - ctx->block_size) / 2;
  keccak_squeeze(ctx, result, digest_len);
  memzero(ctx, sizeof(SHA3_CTX));
}

/* ---------- Init ---------- */

static void sponge_init(SHA3_CTX *ctx, unsigned block_size) {
  memzero(ctx, sizeof(SHA3_CTX));
  ctx->block_size = block_size;
}

__attribute__((weak)) void sha3_224_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHA3_224_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_256_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHA3_256_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_384_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHA3_384_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_512_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHA3_512_BLOCK_LENGTH); }
__attribute__((weak)) void shake128_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHAKE128_BLOCK_LENGTH); }
__attribute__((weak)) void shake256_Init(SHA3_CTX *ctx) { sponge_init(ctx, SHAKE256_BLOCK_LENGTH); }

/* ---------- Update (shared by all modes) ---------- */

__attribute__((weak)) void keccak_Update(SHA3_CTX *ctx, const unsigned char *msg, size_t size) {
  keccak_absorb(ctx, msg, size);
}

/* ---------- Finalize ---------- */

__attribute__((weak)) void sha3_Finalize(SHA3_CTX *ctx, unsigned char *result) {
  keccak_finalize_hash(ctx, 0x06, result);
}

__attribute__((weak)) void keccak_Finalize(SHA3_CTX *ctx, unsigned char *result) {
  keccak_finalize_hash(ctx, 0x01, result);
}

__attribute__((weak)) void shake_Finalize(SHA3_CTX *ctx) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, 0x1F);
}

/* ---------- Squeeze (SHAKE XOF) ---------- */

__attribute__((weak)) void shake_Squeeze(SHA3_CTX *ctx, unsigned char *out, size_t out_len) {
  if (!(ctx->rest & SPONGE_FINALIZED)) keccak_pad(ctx, 0x1F);
  keccak_squeeze(ctx, out, out_len);
}

/* ---------- One-shot convenience ---------- */

__attribute__((weak)) void keccak_256(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  keccak_Update(&ctx, data, len);
  keccak_Finalize(&ctx, digest);
}

__attribute__((weak)) void keccak_512(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_512_Init(&ctx);
  keccak_Update(&ctx, data, len);
  keccak_Finalize(&ctx, digest);
}

__attribute__((weak)) void sha3_256(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  keccak_Update(&ctx, data, len);
  sha3_Finalize(&ctx, digest);
}

__attribute__((weak)) void sha3_512(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_512_Init(&ctx);
  keccak_Update(&ctx, data, len);
  sha3_Finalize(&ctx, digest);
}

__attribute__((weak)) void shake128(const unsigned char *data, size_t len, unsigned char *out, size_t out_len) {
  SHA3_CTX ctx;
  shake128_Init(&ctx);
  keccak_Update(&ctx, data, len);
  shake_Finalize(&ctx);
  shake_Squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(SHA3_CTX));
}

__attribute__((weak)) void shake256(const unsigned char *data, size_t len, unsigned char *out, size_t out_len) {
  SHA3_CTX ctx;
  shake256_Init(&ctx);
  keccak_Update(&ctx, data, len);
  shake_Finalize(&ctx);
  shake_Squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(SHA3_CTX));
}
