// SPDX-License-Identifier: Apache-2.0
// Standalone DES/3DES-EDE implementation (DES removed from mbedtls 4.0)
// Uses uint64_t for 64-bit block operations.
#include <des.h>
#include <string.h>
#include <stdint.h>

// clang-format off

static const uint8_t IP[64] = {
  58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
  57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const uint8_t FP[64] = {
  40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
  38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
  36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
  34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25
};

static const uint8_t E[48] = {
  32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
   8, 9,10,11,12,13, 12,13,14,15,16,17,
  16,17,18,19,20,21, 20,21,22,23,24,25,
  24,25,26,27,28,29, 28,29,30,31,32, 1
};

static const uint8_t P[32] = {
  16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
   2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25
};

/* S-boxes from FIPS 46-3, verified against B-Con/crypto-algorithms reference */
static const uint8_t S[8][64] = {
  {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
    0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
    4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
   15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13},
  {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
    3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
    0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
   13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9},
  {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
   13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
   13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
    1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12},
  { 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
   13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
   10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
    3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14},
  { 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
   14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
    4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
   11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3},
  {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
   10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
    9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
    4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13},
  { 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
   13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
    1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
    6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12},
  {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
    1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
    7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
    2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11}
};


static const uint8_t PC1[56] = {
  57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
  10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
  63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
  14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4
};

static const uint8_t PC2[48] = {
  14,17,11,24, 1, 5, 3,28,15, 6,21,10,
  23,19,12, 4,26, 8,16, 7,27,20,13, 2,
  41,52,31,37,47,55,30,40,51,45,33,48,
  44,49,39,56,34,53,46,42,50,36,29,32
};

static const uint8_t SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

// clang-format on

/* Bit numbering: bit 1 = MSB of the block (bit 63 of uint64_t) */
static inline int getbit64(uint64_t v, int bit) { return (int)((v >> (64 - bit)) & 1); }

static uint64_t permute64(uint64_t in, const uint8_t *table, int n) {
  uint64_t out = 0;
  for (int i = 0; i < n; i++) {
    out |= ((uint64_t)getbit64(in, table[i])) << (63 - i);
  }
  return out;
}

static uint64_t bytes_to_u64(const uint8_t b[8]) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
  return v;
}

static void u64_to_bytes(uint64_t v, uint8_t b[8]) {
  for (int i = 7; i >= 0; i--) {
    b[i] = (uint8_t)(v & 0xFF);
    v >>= 8;
  }
}

/* Expand uint32_t (in bits 1-32 of a 64-bit) to 48 bits in a uint64_t */
static uint64_t expand_r(uint32_t R) {
  uint64_t r64 = (uint64_t)R << 32;
  uint64_t out = 0;
  for (int i = 0; i < 48; i++) {
    out |= ((uint64_t)((r64 >> (64 - E[i])) & 1)) << (63 - i);
  }
  return out;
}

static uint32_t feistel(uint32_t R, uint64_t subkey) {
  /* Expand R to 48 bits and XOR with subkey */
  uint64_t er = expand_r(R) ^ subkey;

  /* S-box substitution: 48 bits -> 32 bits */
  uint32_t sbox_out = 0;
  for (int i = 0; i < 8; i++) {
    /* Extract 6-bit group: bits (i*6+1) through (i*6+6) from MSB-aligned er */
    int shift = 58 - i * 6;
    int val = (int)((er >> shift) & 0x3F);
    int row = ((val >> 4) & 0x02) | (val & 0x01);
    int col = (val >> 1) & 0x0F;
    sbox_out |= ((uint32_t)S[i][row * 16 + col]) << (4 * (7 - i));
  }

  /* Apply permutation P (32 bits) */
  uint64_t sb64 = (uint64_t)sbox_out << 32;
  uint32_t result = 0;
  for (int i = 0; i < 32; i++) {
    result |= ((uint32_t)((sb64 >> (64 - P[i])) & 1)) << (31 - i);
  }
  return result;
}

static void des_generate_subkeys(const uint8_t key[8], uint64_t subkeys[16]) {
  uint64_t k64 = bytes_to_u64(key);

  /* PC1: 64 bits -> 56 bits (stored in top 56 bits of uint64_t) */
  uint64_t pc1 = permute64(k64, PC1, 56);

  /* Split into C (bits 1-28) and D (bits 29-56) */
  uint32_t C = (uint32_t)(pc1 >> 36) & 0x0FFFFFFF;
  uint32_t D = (uint32_t)(pc1 >> 8) & 0x0FFFFFFF;

  for (int round = 0; round < 16; round++) {
    for (int s = 0; s < SHIFTS[round]; s++) {
      C = ((C << 1) & 0x0FFFFFFF) | ((C >> 27) & 1);
      D = ((D << 1) & 0x0FFFFFFF) | ((D >> 27) & 1);
    }
    /* Recombine C and D into 56-bit value, apply PC2 to get 48-bit subkey */
    uint64_t cd = ((uint64_t)C << 36) | ((uint64_t)D << 8);
    subkeys[round] = permute64(cd, PC2, 48);
  }
}

static void des_process(const uint8_t in[8], uint8_t out[8], const uint64_t subkeys[16]) {
  uint64_t block = bytes_to_u64(in);

  /* Initial permutation */
  block = permute64(block, IP, 64);

  uint32_t L = (uint32_t)(block >> 32);
  uint32_t R = (uint32_t)(block & 0xFFFFFFFF);

  for (int round = 0; round < 16; round++) {
    uint32_t tmp = R;
    R = L ^ feistel(R, subkeys[round]);
    L = tmp;
  }

  /* Recombine (note: swap L and R) */
  uint64_t pre_fp = ((uint64_t)R << 32) | (uint64_t)L;

  /* Final permutation */
  uint64_t result = permute64(pre_fp, FP, 64);
  u64_to_bytes(result, out);
}

__attribute__((weak)) int des_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  uint64_t subkeys[16];
  des_generate_subkeys(key, subkeys);
  des_process(in, out, subkeys);
  return 0;
}

__attribute__((weak)) int des_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  uint64_t subkeys[16];
  des_generate_subkeys(key, subkeys);
  /* Reverse subkey order */
  uint64_t rev[16];
  for (int i = 0; i < 16; i++) rev[i] = subkeys[15 - i];
  des_process(in, out, rev);
  return 0;
}

__attribute__((weak)) int tdes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  uint8_t tmp[8];
  des_enc(in, tmp, key);
  des_dec(tmp, out, key + 8);
  des_enc(out, tmp, key + 16);
  memcpy(out, tmp, 8);
  return 0;
}

__attribute__((weak)) int tdes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
  uint8_t tmp[8];
  des_dec(in, tmp, key + 16);
  des_enc(tmp, out, key + 8);
  des_dec(out, tmp, key);
  memcpy(out, tmp, 8);
  return 0;
}
