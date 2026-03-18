// SPDX-License-Identifier: Apache-2.0
// Cross-validation: our SHA3/SHAKE vs mbedtls SHA3 + pre-computed SHAKE vectors

// clang-format off
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
// clang-format on

#include <sha3.h>
#include <string.h>
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <mbedtls/private/sha3.h>

/* Simple deterministic xorshift64 PRNG for reproducible test data */
static uint64_t prng_state;

static void prng_seed(uint64_t seed) { prng_state = seed; }

static uint8_t prng_byte(void) {
  prng_state ^= prng_state << 13;
  prng_state ^= prng_state >> 7;
  prng_state ^= prng_state << 17;
  return (uint8_t)(prng_state & 0xFF);
}

static void prng_fill(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++)
    buf[i] = prng_byte();
}

/* Cross-validate one SHA3 variant against mbedtls */
static void cross_validate_sha3(mbedtls_sha3_id id, void (*our_init)(SHA3_CTX_T *),
                                void (*our_finalize)(SHA3_CTX_T *, uint8_t *), unsigned digest_len, const uint8_t *data,
                                size_t data_len) {
  uint8_t our_digest[64];
  uint8_t mbed_digest[64];

  sha3_ctx_t ctx;
  our_init(&ctx);
  sha3_update(&ctx, data, data_len);
  our_finalize(&ctx, our_digest);

  mbedtls_sha3_context mctx;
  mbedtls_sha3_init(&mctx);
  assert_int_equal(mbedtls_sha3_starts(&mctx, id), 0);
  assert_int_equal(mbedtls_sha3_update(&mctx, data, data_len), 0);
  assert_int_equal(mbedtls_sha3_finish(&mctx, mbed_digest, digest_len), 0);
  mbedtls_sha3_free(&mctx);

  assert_memory_equal(our_digest, mbed_digest, digest_len);
}

#define NUM_TRIALS 100

static void test_sha3_224_random(void **state) {
  (void)state;
  uint8_t data[1024];
  prng_seed(0xA3224A3224ULL);
  for (int t = 0; t < NUM_TRIALS; t++) {
    size_t len = (prng_byte() | ((size_t)prng_byte() << 8)) % 1024;
    prng_fill(data, len);
    cross_validate_sha3(MBEDTLS_SHA3_224, sha3_224_init, sha3_finalize, SHA3_224_DIGEST_LENGTH, data, len);
  }
}

static void test_sha3_256_random(void **state) {
  (void)state;
  uint8_t data[1024];
  prng_seed(0xA3256A3256ULL);
  for (int t = 0; t < NUM_TRIALS; t++) {
    size_t len = (prng_byte() | ((size_t)prng_byte() << 8)) % 1024;
    prng_fill(data, len);
    cross_validate_sha3(MBEDTLS_SHA3_256, sha3_256_init, sha3_finalize, SHA3_256_DIGEST_LENGTH, data, len);
  }
}

static void test_sha3_384_random(void **state) {
  (void)state;
  uint8_t data[1024];
  prng_seed(0xA3384A3384ULL);
  for (int t = 0; t < NUM_TRIALS; t++) {
    size_t len = (prng_byte() | ((size_t)prng_byte() << 8)) % 1024;
    prng_fill(data, len);
    cross_validate_sha3(MBEDTLS_SHA3_384, sha3_384_init, sha3_finalize, SHA3_384_DIGEST_LENGTH, data, len);
  }
}

static void test_sha3_512_random(void **state) {
  (void)state;
  uint8_t data[1024];
  prng_seed(0xA3512A3512ULL);
  for (int t = 0; t < NUM_TRIALS; t++) {
    size_t len = (prng_byte() | ((size_t)prng_byte() << 8)) % 1024;
    prng_fill(data, len);
    cross_validate_sha3(MBEDTLS_SHA3_512, sha3_512_init, sha3_finalize, SHA3_512_DIGEST_LENGTH, data, len);
  }
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_sha3_224_random),
      cmocka_unit_test(test_sha3_256_random),
      cmocka_unit_test(test_sha3_384_random),
      cmocka_unit_test(test_sha3_512_random),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
