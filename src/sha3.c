/*
 * SHA-3 / Keccak / SHAKE implementation based on FIPS 202.
 *
 * Keccak-f[1600] permutation derived from Mbed TLS (Apache-2.0 OR GPL-2.0-or-later),
 * using compressed iota round constants to minimize ROM usage.
 *
 * SHA-3, Keccak, and SHAKE wrappers written for canokey-crypto.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sha3.h"
#include <memzero.h>
#include <string.h>

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

/* ---------- Internal absorb / squeeze helpers ---------- */

#define SHA3_FINALIZED 0x80000000u
#define SHA3_SQUEEZED 0x40000000u

/*
 * Absorb data into the sponge. Works for SHA-3, Keccak, and SHAKE.
 * ctx->block_size is the rate in bytes.
 */
static void keccak_absorb(SHA3_CTX *ctx, const uint8_t *data, size_t len) {
  unsigned idx = ctx->rest & ~(SHA3_FINALIZED | SHA3_SQUEEZED);
  const unsigned rate = ctx->block_size;

  ctx->rest = idx; /* clear flags during absorb (re-absorb after squeeze is illegal) */

  while (len > 0) {
    unsigned todo = rate - idx;
    if (todo > len) todo = (unsigned)len;

    /* XOR data into state byte-by-byte */
    for (unsigned i = 0; i < todo; i++) {
      unsigned pos = idx + i;
      ((uint8_t *)ctx->hash)[pos] ^= data[i];
    }
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

/*
 * Finalize (pad) the sponge. pad_byte differentiates:
 *   SHA-3:  0x06
 *   Keccak: 0x01
 *   SHAKE:  0x1F
 */
static void keccak_pad(SHA3_CTX *ctx, uint8_t pad_byte) {
  unsigned idx = ctx->rest & ~(SHA3_FINALIZED | SHA3_SQUEEZED);
  const unsigned rate = ctx->block_size;

  ((uint8_t *)ctx->hash)[idx] ^= pad_byte;
  ((uint8_t *)ctx->hash)[rate - 1] ^= 0x80;
  keccak_f1600(ctx->hash);

  ctx->rest = SHA3_FINALIZED;
}

/*
 * Squeeze output from the sponge (for XOF: SHAKE).
 * May be called multiple times after finalize.
 */
static void keccak_squeeze(SHA3_CTX *ctx, uint8_t *out, size_t out_len) {
  const unsigned rate = ctx->block_size;
  /* squeeze_pos is stored in low bits when SQUEEZED flag is set */
  unsigned pos = (ctx->rest & SHA3_SQUEEZED) ? (ctx->rest & 0xFFFF) : 0;

  ctx->rest = SHA3_FINALIZED | SHA3_SQUEEZED | pos;

  while (out_len > 0) {
    if (pos == rate) {
      keccak_f1600(ctx->hash);
      pos = 0;
    }
    unsigned avail = rate - pos;
    unsigned todo = (out_len < avail) ? (unsigned)out_len : avail;
    memcpy(out, (uint8_t *)ctx->hash + pos, todo);
    pos += todo;
    out += todo;
    out_len -= todo;
  }
  ctx->rest = SHA3_FINALIZED | SHA3_SQUEEZED | pos;
}

/* ---------- SHA-3 Init ---------- */

static void sha3_init(SHA3_CTX *ctx, unsigned block_size) {
  memzero(ctx, sizeof(SHA3_CTX));
  ctx->block_size = block_size;
}

__attribute__((weak)) void sha3_224_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHA3_224_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_256_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHA3_256_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_384_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHA3_384_BLOCK_LENGTH); }
__attribute__((weak)) void sha3_512_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHA3_512_BLOCK_LENGTH); }

/* ---------- SHA-3 / Keccak Update ---------- */

__attribute__((weak)) void sha3_Update(SHA3_CTX *ctx, const unsigned char *msg, size_t size) {
  keccak_absorb(ctx, msg, size);
}

/* ---------- SHA-3 Final (pad = 0x06) ---------- */

__attribute__((weak)) void sha3_Final(SHA3_CTX *ctx, unsigned char *result) {
  if (!(ctx->rest & SHA3_FINALIZED)) keccak_pad(ctx, 0x06);
  /* Output: hash_size = 200 - 2 * (200 - block_size) / 2 ... simpler: */
  unsigned digest_len = (200 - ctx->block_size) / 2;
  memcpy(result, ctx->hash, digest_len);
  memzero(ctx, sizeof(SHA3_CTX));
}

/* ---------- Keccak Final (pad = 0x01) ---------- */

__attribute__((weak)) void keccak_Final(SHA3_CTX *ctx, unsigned char *result) {
  if (!(ctx->rest & SHA3_FINALIZED)) keccak_pad(ctx, 0x01);
  unsigned digest_len = (200 - ctx->block_size) / 2;
  memcpy(result, ctx->hash, digest_len);
  memzero(ctx, sizeof(SHA3_CTX));
}

/* ---------- Convenience one-shot ---------- */

__attribute__((weak)) void keccak_256(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, data, len);
  keccak_Final(&ctx, digest);
}

__attribute__((weak)) void keccak_512(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_512_Init(&ctx);
  sha3_Update(&ctx, data, len);
  keccak_Final(&ctx, digest);
}

__attribute__((weak)) void sha3_256(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, data, len);
  sha3_Final(&ctx, digest);
}

__attribute__((weak)) void sha3_512(const unsigned char *data, size_t len, unsigned char *digest) {
  SHA3_CTX ctx;
  sha3_512_Init(&ctx);
  sha3_Update(&ctx, data, len);
  sha3_Final(&ctx, digest);
}

/* ---------- SHAKE128 / SHAKE256 ---------- */

__attribute__((weak)) void shake128_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHAKE128_BLOCK_LENGTH); }
__attribute__((weak)) void shake256_Init(SHA3_CTX *ctx) { sha3_init(ctx, SHAKE256_BLOCK_LENGTH); }

__attribute__((weak)) void shake_Update(SHA3_CTX *ctx, const unsigned char *msg, size_t size) {
  keccak_absorb(ctx, msg, size);
}

__attribute__((weak)) void shake_Finalize(SHA3_CTX *ctx) {
  if (!(ctx->rest & SHA3_FINALIZED)) keccak_pad(ctx, 0x1F);
}

__attribute__((weak)) void shake_Squeeze(SHA3_CTX *ctx, unsigned char *out, size_t out_len) {
  if (!(ctx->rest & SHA3_FINALIZED)) keccak_pad(ctx, 0x1F);
  keccak_squeeze(ctx, out, out_len);
}

/* One-shot SHAKE with fixed output length */
__attribute__((weak)) void shake128(const unsigned char *data, size_t len, unsigned char *out, size_t out_len) {
  SHA3_CTX ctx;
  shake128_Init(&ctx);
  shake_Update(&ctx, data, len);
  shake_Finalize(&ctx);
  shake_Squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(SHA3_CTX));
}

__attribute__((weak)) void shake256(const unsigned char *data, size_t len, unsigned char *out, size_t out_len) {
  SHA3_CTX ctx;
  shake256_Init(&ctx);
  shake_Update(&ctx, data, len);
  shake_Finalize(&ctx);
  shake_Squeeze(&ctx, out, out_len);
  memzero(&ctx, sizeof(SHA3_CTX));
}
