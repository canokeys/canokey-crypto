/* SPDX-License-Identifier: Apache-2.0 */
/* Exhaustive valid byte ranges and four pointer offsets; no mutation campaign. */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <string.h>
void KeccakP1600_AddBytes(void *, const unsigned char *, unsigned, unsigned);
void KeccakP1600_OverwriteBytes(void *, const unsigned char *, unsigned, unsigned);
void KeccakP1600_OverwriteWithZeroes(void *, unsigned);
void KeccakP1600_ExtractBytes(const void *, unsigned char *, unsigned, unsigned);
void KeccakP1600_ExtractAndAddBytes(const void *, const unsigned char *, unsigned char *, unsigned, unsigned);

/* Independent bit-by-bit canonical-byte to 32bi reference. */
static void encode(uint32_t state[50], const uint8_t bytes[200]) {
  memset(state, 0, 200);
  for (unsigned bit = 0; bit < 1600; ++bit)
    state[(bit / 64)*2 + (bit & 1)] |= (uint32_t)((bytes[bit/8] >> (bit%8)) & 1) << ((bit%64)/2);
}
static void check_state(const uint32_t actual[50], const uint8_t bytes[200]) {
  uint32_t expected[50]; encode(expected, bytes);
  assert(!memcmp(actual, expected, 200));
}
int main(void) {
  uint8_t initial[200], source[204], output[204], expected[200];
  for (unsigned i = 0; i < 200; ++i) initial[i] = (uint8_t)(11*i+3);
  for (unsigned alignment = 0; alignment < 4; ++alignment) {
    uint8_t *input = source + alignment;
    for (unsigned i = 0; i < 200; ++i) input[i] = (uint8_t)(7*i+1);
    for (unsigned offset = 0; offset <= 200; ++offset) {
      for (unsigned length = 0; length <= 200-offset; ++length) {
        uint32_t state[50], saved[50];
        memcpy(expected, initial, 200); encode(state, initial);
        KeccakP1600_AddBytes(state, input, offset, length);
        for (unsigned i = 0; i < length; ++i) expected[offset+i] ^= input[i];
        check_state(state, expected);
        KeccakP1600_OverwriteBytes(state, input, offset, length);
        memcpy(expected+offset, input, length); check_state(state, expected);
        memcpy(saved, state, 200);
        memset(output, 0xa5, sizeof(output));
        KeccakP1600_ExtractBytes(state, output+alignment, offset, length);
        assert(!memcmp(output+alignment, expected+offset, length));
        for (unsigned i = 0; i < sizeof(output); ++i)
          if (i < alignment || i >= alignment+length) assert(output[i] == 0xa5);
        memset(output, 0xa5, sizeof(output));
        KeccakP1600_ExtractAndAddBytes(state, input, output+alignment, offset, length);
        for (unsigned i = 0; i < length; ++i) assert(output[alignment+i] == (uint8_t)(input[i]^expected[offset+i]));
        for (unsigned i = 0; i < sizeof(output); ++i)
          if (i < alignment || i >= alignment+length) assert(output[i] == 0xa5);
        memcpy(output+alignment, input, length);
        KeccakP1600_ExtractAndAddBytes(state, output+alignment, output+alignment, offset, length);
        for (unsigned i = 0; i < length; ++i) assert(output[alignment+i] == (uint8_t)(input[i]^expected[offset+i]));
        assert(!memcmp(state, saved, 200));
      }
    }
  }
  for (unsigned length = 0; length <= 200; ++length) {
    uint32_t state[50]; encode(state, initial);
    memcpy(expected, initial, 200); memset(expected, 0, length);
    KeccakP1600_OverwriteWithZeroes(state, length); check_state(state, expected);
  }
  return 0;
}
