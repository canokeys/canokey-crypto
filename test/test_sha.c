// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>
#include <sha.h>
#include <hmac.h>

static void test_sha1(void **state) {
  (void)state;
  uint8_t buf[20];
  uint8_t expected[] = {0x5b, 0xa9, 0x3c, 0x9d, 0xb0, 0xcf, 0xf9,
                        0x3f, 0x52, 0xb5, 0x21, 0xd7, 0x42, 0x0e,
                        0x43, 0xf6, 0xed, 0xa2, 0x78, 0x4f};
  buf[0] = 0;
  sha1_raw(buf, 1, buf);
  for (int i = 0; i != 20; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_sha256(void **state) {
  (void)state;
  uint8_t buf[32];
  uint8_t expected[] = {0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
                        0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
                        0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
                        0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d};
  buf[0] = 0;
  sha256_raw(buf, 1, buf);
  for (int i = 0; i != 32; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_keccak256(void **state) {
  (void)state;
  uint8_t buf[32];
  uint8_t expected[] = {0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14,
                        0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
                        0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91,
                        0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a};
  buf[0] = 0;
  SHA3_CTX ctx;
  keccak_256_Init(&ctx);
  keccak_Update(&ctx, buf, 1);
  keccak_Final(&ctx, buf);
  for (int i = 0; i != 32; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_sha3_256(void **state) {
  (void)state;
  uint8_t buf[32];
  uint8_t expected[] = {0x5d, 0x53, 0x46, 0x9f, 0x20, 0xfe, 0xf4, 0xf8,
                        0xea, 0xb5, 0x2b, 0x88, 0x04, 0x4e, 0xde, 0x69,
                        0xc7, 0x7a, 0x6a, 0x68, 0xa6, 0x07, 0x28, 0x60,
                        0x9f, 0xc4, 0xa6, 0x5f, 0xf5, 0x31, 0xe7, 0xd0};
  buf[0] = 0;
  SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, buf, 1);
  sha3_Final(&ctx, buf);
  for (int i = 0; i != 32; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_hmac_sha1(void **state) {
  (void)state;
  uint8_t key[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t buf[20];
  uint8_t expected[] = {0xf0, 0xfb, 0x6b, 0x43, 0x7a, 0x6a, 0x18, 0x3b, 0xc3,
                        0x28, 0x8d, 0xc6, 0xd4, 0xa1, 0x03, 0x34, 0x26, 0x5e,
                        0x47, 0x0f};
  buf[0] = 0;
  HMAC_SHA1_CTX ctx;
  hmac_sha1_Init(&ctx, key, sizeof(key));
  hmac_sha1_Update(&ctx, buf, 1);
  hmac_sha1_Final(&ctx, buf);
  for (int i = 0; i != 20; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_hmac_sha256(void **state) {
  (void)state;
  uint8_t key[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t buf[32];
  uint8_t expected[] = {0xc0, 0xd6, 0xf7, 0xec, 0x99, 0xb6, 0xfb, 0xfe,
                        0xc1, 0xe0, 0xbe, 0xd5, 0xa1, 0x0d, 0xd1, 0xe5,
                        0xcd, 0xe7, 0xbe, 0x11, 0x4c, 0x41, 0x71, 0x81,
                        0x69, 0xc7, 0xd6, 0x3e, 0x67, 0x05, 0x6d, 0x28};
  buf[0] = 0;
  HMAC_SHA256_CTX ctx;
  hmac_sha256_Init(&ctx, key, sizeof(key));
  hmac_sha256_Update(&ctx, buf, 1);
  hmac_sha256_Final(&ctx, buf);
  for (int i = 0; i != 32; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_sha1),
      cmocka_unit_test(test_sha256),
      cmocka_unit_test(test_keccak256),
      cmocka_unit_test(test_sha3_256),
      cmocka_unit_test(test_hmac_sha1),
      cmocka_unit_test(test_hmac_sha256),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}