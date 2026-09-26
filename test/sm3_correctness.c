/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed SM3 vectors, alignment, padding and all two-fragment boundaries. */
#undef NDEBUG
#include <assert.h>
#include <sm3.h>
#include <string.h>

static unsigned digit(char c) { return c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10); }
static void check(const uint8_t *input, size_t length, const char *hex) {
  uint8_t expected[32];
  for (unsigned i = 0; i < 32; ++i) expected[i] = (uint8_t)(16 * digit(hex[2*i]) + digit(hex[2*i+1]));
  for (unsigned alignment = 0; alignment < 4; ++alignment) {
    uint8_t arena[140], output[40];
    memset(arena, 0xa5, sizeof(arena));
    memcpy(arena + alignment, input, length);
    for (size_t split = 0; split <= length; ++split) {
      memset(output, 0xa5, sizeof(output));
      sm3_ctx_t ctx;
      sm3_init(&ctx);
      sm3_update(&ctx, arena + alignment, split);
      sm3_update(&ctx, arena + alignment + split, length - split);
      sm3_final(&ctx, output + alignment);
      assert(!memcmp(output + alignment, expected, 32));
      for (unsigned i = 0; i < sizeof(output); ++i)
        if (i < alignment || i >= alignment + 32) assert(output[i] == 0xa5);
      for (unsigned i = 0; i < sizeof(ctx); ++i) assert(((const uint8_t *)&ctx)[i] == 0);
      assert(!memcmp(arena + alignment, input, length));
    }
    sm3_raw(arena + alignment, length, arena + alignment);
    assert(!memcmp(arena + alignment, expected, 32));
  }
}
int main(void) {
  /* GM/T 0004 examples. */
  check((const uint8_t *)"abc", 3, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
  uint8_t repeated[64];
  for (unsigned i = 0; i < sizeof(repeated); ++i) repeated[i] = (uint8_t)"abcd"[i % 4];
  check(repeated, sizeof(repeated), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
  /* Independently generated with OpenSSL SM3 for bytes (7*i+1) mod 256. */
  static const struct { size_t length; const char *digest; } cases[] = {
    {0, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
    {3, "9942e6312deab40145c588f6af44d59dad79e6fea60a924efefe21a2079d3ede"},
    {55, "1b054d2273b72898f72f0c5fdab0d135346f0a5cad549e6be576e1a9ba4f6db0"},
    {56, "3314c3103d64dcbdad4a28a4bdd827b5b562d89bc41683b330490e226979d957"},
    {63, "5078a2d8ecfed3150e7893e246fa8f0c0bdb9b10877857c3c6b73a27cebc08fd"},
    {64, "63bec16a53556235bbb515168e370cb84be8fcefcd9e1179fc18a3673170dc25"},
    {65, "7707917e48fe510e5ffc5f7c71c4d76fecfadca14ee2fe99054d5619836786ca"},
    {127, "464bc2774ccdceb3c1d240d3075959cd23ad247ee49e713fc62e330c00f67ac0"},
    {128, "7e4d79172d70846cc6d582f5f1263b8fac46fc34cccdddef5c71110f21ef16d3"},
    {129, "ba7c7f0078b4e7b9e7c93f69aad3b571b504a8256f5682d0d7454973d6b0f761"},
  };
  uint8_t pattern[129];
  for (unsigned i = 0; i < sizeof(pattern); ++i) pattern[i] = (uint8_t)(7*i+1);
  for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
    check(pattern, cases[i].length, cases[i].digest);
  return 0;
}
