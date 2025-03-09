// SPDX-License-Identifier: Apache-2.0
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>

#include "ecc.h"
#include "ecdsa-generic.h"
#include "nist256p1.h"
#include "crypto-util.h"

#define ECC_TEST_PRELUDE(TYPE) ecc_key_t key; \
const int KEY_TYPE = TYPE; \
const size_t KEY_LEN = PUBLIC_KEY_LENGTH[KEY_TYPE]; \
const size_t SIG_LEN = SIGNATURE_LENGTH[KEY_TYPE]; \
__attribute__((unused)) uint8_t pub[KEY_LEN]; \
__attribute__((unused)) uint8_t sig[SIG_LEN]; \
ecc_generate(KEY_TYPE, &key);

static void test_ecc_keygen(void **state) {
  (void)state;
  {
    // Test SECP256R1
    ECC_TEST_PRELUDE(SECP256R1);
    uint8_t expected_pubkey[KEY_LEN];
    ecdsa_get_public_key(&nist256p1, key.pri, expected_pubkey);
    assert_memory_equal(key.pub, expected_pubkey, KEY_LEN);
  }
}

static void test_ecdsa_sign(void **state) {
  (void)state;
  {
    // Test SECP256R1
    ECC_TEST_PRELUDE(SECP256R1);
    uint8_t digest[32] = {0x98, 0x34, 0x87, 0x6d, 0xcf, 0xb0, 0x5c, 0xb1, 0x67, 0xa5, 0xc2, 0x49, 0x53, 0xeb, 0xa5, 0x8c,
                          0x4a, 0xc8, 0x9b, 0x1a, 0xdf, 0x57, 0xf2, 0x8f, 0x2f, 0x9d, 0x09, 0xaf, 0x10, 0x7e, 0xe8, 0xf0};
    ecc_sign(SECP256R1, &key, digest, sizeof(digest), sig);
    assert_int_equal(ecdsa_verify_digest(&nist256p1, key.pub, sig, digest), 0);

    memcpy(key.pri, "\x50\x5a\x4f\xcf\xa6\xe2\x20\xba\x55\x09\x58\xab\xc4\xf2\x39\x05\xe9\xdb\x2a\x2b\x5a\xca\x29\xad\x72\x89\x36\x70\x2f\x9a\x69\xea", 32);
    memcpy(digest, "\x11\x54\xaf\xd4\xf1\x49\x72\x2e\xc5\x90\xdf\x9c\xae\xda\x64\xfe\xef\x82\xcc\x29\xda\x1a\x04\x23\xf1\xf4\xf3\xa4\x8a\x56\x8b\x63", 32);
    ecc_sign(SM2, &key, digest, sizeof(digest), sig);
    uint8_t expected_sig[] = {0xf1,0x50,0x7e,0xc1,0x7c,0x63,0x40,0xca,0x2f,0x4c,0x74,0x48,0xa0,0xb2,0x76,0x9f,0xfa,0xe8,0x27,0x01,0x7a,0x2e,0xa9,0xed,0x4e,0x62,0xd7,0x31,0x41,0xd2,0xc9,0x5f,0x80,0xd7,0x92,0x5f,0x9a,0xd9,0xd6,0x11,0x67,0x12,0x9f,0x74,0xca,0x9d,0x4a,0xe5,0xab,0xb1,0x89,0x60,0x3c,0x7b,0xd9,0x6e,0xce,0x77,0xb4,0x45,0xec,0x76,0xf2,0xf7};
    assert_memory_equal(sig, expected_sig, 64);
  }
}

static void test_ecc_verify_private_key(void **state) {
  (void)state;
  ecc_key_t key;
  memset(key.pri, 0x01, 32);
  assert_int_equal(ecc_verify_private_key(SECP256R1, &key), 1);
  memset(key.pri, 0xFF, 32);
  assert_int_equal(ecc_verify_private_key(SECP256R1, &key), 0);
}

static void test_ecc_get_public_key(void **state) {
  (void)state;
  for (int i = 0; i < KEY_TYPE_PKC_END; i++) {
    if (!IS_ECC(i)) continue;
    ECC_TEST_PRELUDE(i);
    uint8_t expected_pubkey[KEY_LEN];
    memcpy(expected_pubkey, key.pub, KEY_LEN);
    ecc_complete_key(i, &key);
    assert_memory_equal(key.pub, expected_pubkey, KEY_LEN);
  }
}

static void test_ecdh(void **state) {
  (void)state;
  ecc_key_t key1, key2;
  uint8_t out[64], expected[64];
  ecc_generate(SECP256R1, &key1);
  ecc_generate(SECP256R1, &key2);
  ecdh(SECP256R1, key1.pri, key2.pub, out);

  curve_point pub;
  ecdsa_read_pubkey(&nist256p1, key2.pub, &pub);
  bignum256 s;
  bn_read_be(key1.pri, &s);
  point_multiply(&nist256p1, &s, &pub, &pub);
  bn_write_be(&pub.x, expected);
  bn_write_be(&pub.y, expected + 32);

  for (int i = 0; i != 64; ++i) {
    assert_int_equal(out[i], expected[i]);
  }
}

static void test_sig2ansi(void **state) {
  (void)state;
  uint8_t input[128] = {0x6c, 0x33, 0x84, 0x78, 0xea, 0x14, 0x68, 0xd4, 0xef, 0x9a, 0xe3, 0xa2, 0x65, 0x12, 0x1c, 0x63,
                        0x74, 0x86, 0x1c, 0x90, 0x21, 0xc5, 0x5b, 0x5d, 0xc1, 0x98, 0xbb, 0x7e, 0x3d, 0xe1, 0x8d, 0x9a,
                        0x00, 0x18, 0x9b, 0x39, 0x8c, 0x56, 0xe9, 0x95, 0xcd, 0xf5, 0xde, 0xa3, 0x70, 0xf6, 0xc3, 0x53,
                        0xd2, 0xa4, 0xd2, 0x53, 0x23, 0xb2, 0xa4, 0x4a, 0xca, 0xc1, 0xad, 0x5a, 0x15, 0xe1, 0x73, 0xf6};
  uint8_t expected[128] = {0x30, 0x43, 0x02, 0x20, 0x6c, 0x33, 0x84, 0x78, 0xea, 0x14, 0x68, 0xd4, 0xef, 0x9a,
                           0xe3, 0xa2, 0x65, 0x12, 0x1c, 0x63, 0x74, 0x86, 0x1c, 0x90, 0x21, 0xc5, 0x5b, 0x5d,
                           0xc1, 0x98, 0xbb, 0x7e, 0x3d, 0xe1, 0x8d, 0x9a, 0x02, 0x1f, 0x18, 0x9b, 0x39, 0x8c,
                           0x56, 0xe9, 0x95, 0xcd, 0xf5, 0xde, 0xa3, 0x70, 0xf6, 0xc3, 0x53, 0xd2, 0xa4, 0xd2,
                           0x53, 0x23, 0xb2, 0xa4, 0x4a, 0xca, 0xc1, 0xad, 0x5a, 0x15, 0xe1, 0x73, 0xf6};
  size_t len = ecdsa_sig2ansi(32, input, input);
  assert_int_equal(len, 69);
  for (int i = 0; i != len; ++i) {
    assert_int_equal(input[i], expected[i]);
  }

  memcpy(input,
         "\xc5\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36\x4c\x15\x8a\x2f\x3a\x05\x18\x67"
         "\x44\x21\x74\x92\x39\x1e\x0b\x89\x52\x09\xce\x24\xdf\x74\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20"
         "\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         64);
  memcpy(expected,
         "\x30\x45\x02\x21\x00\xc5\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36"
         "\x4c\x15\x8a\x2f\x3a\x05\x18\x67\x44\x21\x74\x92\x39\x02\x20\x1e\x0b\x89\x52\x09\xce\x24\xdf\x74"
         "\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         71);
  len = ecdsa_sig2ansi(32, input, input);
  assert_int_equal(len, 71);
  for (int i = 0; i != len; ++i) {
    assert_int_equal(input[i], expected[i]);
  }

  memcpy(input,
         "\x15\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36\x4c\x15\x8a\x2f\x3a\x05\x18\x67"
         "\x44\x21\x74\x92\x39\x1e\x0b\x89\x52\x09\xce\x24\xdf\x74\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20"
         "\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         64);
  memcpy(expected,
         "\x30\x44\x02\x20\x15\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36"
         "\x4c\x15\x8a\x2f\x3a\x05\x18\x67\x44\x21\x74\x92\x39\x02\x20\x1e\x0b\x89\x52\x09\xce\x24\xdf\x74"
         "\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         70);
  len = ecdsa_sig2ansi(32, input, input);
  assert_int_equal(len, 70);
  for (int i = 0; i != len; ++i) {
    assert_int_equal(input[i], expected[i]);
  }

  memcpy(input,
         "\x15\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36\x4c\x15\x8a\x2f\x3a\x05\x18\x67"
         "\x44\x21\x74\x92\x39\x00\xbb\x89\x52\x09\xce\x24\xdf\x74\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20"
         "\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         64);
  memcpy(expected,
         "\x30\x44\x02\x20\x15\xad\x76\xe8\x7a\xb5\xc6\xe0\xdf\xf7\xc3\xa0\x30\xf6\x96\xa5\x8b\x10\x36"
         "\x4c\x15\x8a\x2f\x3a\x05\x18\x67\x44\x21\x74\x92\x39\x02\x20\x00\xbb\x89\x52\x09\xce\x24\xdf\x74"
         "\x36\xd8\x6c\xe6\x34\xcf\x65\x71\x89\x81\x51\x20\x20\xd6\x4d\xa3\x30\xbc\x65\x4a\xe4\xf6\xde",
         70);
  len = ecdsa_sig2ansi(32, input, input);
  assert_int_equal(len, 70);
  for (int i = 0; i != len; ++i) {
    assert_int_equal(input[i], expected[i]);
  }
}

static void test_sm2_z(void **state) {
  (void)state;
  const uint8_t id[] = {16, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                        0x38};
  const uint8_t expected[32] = {0x60, 0xf6, 0x87, 0x2d, 0x8b, 0xa1, 0x55, 0x15, 0x59, 0xe0, 0x27, 0x04, 0x82, 0x3c,
                                0xb3, 0x55, 0xb4, 0x4c, 0xd4, 0xc1, 0x81, 0xd7, 0xfa, 0xf4, 0x1b, 0xe4, 0x24, 0x7c,
                                0x99, 0xf7, 0xe2, 0xb0};
  uint8_t out[32];
  ecc_key_t key;
  memcpy(key.pub, "\x10\x2a\xe6\xa8\x42\x4f\x20\xaf\xb7\xfb\x35\xde\xf5\x29\x78\x88\x24\x03\x98\x6e\x40\x5d\x0a\xa6\xc7"
                  "\xf4\x36\xc4\x4d\x49\x95\x8c\xae\x1d\x93\x44\xf9\x36\x16\xab\xd9\x17\x10\x46\xb8\xf8\x3a\xdd\x6b\x4f"
                  "\x1c\xcf\x86\x98\x74\x5f\xa3\x32\x57\x12\x37\x66\xa3\xc6", 64);
  sm2_z(id, &key, out);
  for (int i = 0; i != 32; ++i) {
    assert_int_equal(out[i], expected[i]);
  }
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ecc_keygen),
      cmocka_unit_test(test_ecdsa_sign),
      cmocka_unit_test(test_ecc_verify_private_key),
      cmocka_unit_test(test_ecc_get_public_key),
      cmocka_unit_test(test_ecdh),
      cmocka_unit_test(test_sig2ansi),
      cmocka_unit_test(test_sm2_z),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

#undef ECC_TEST_PRELUDE