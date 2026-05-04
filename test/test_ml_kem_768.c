// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <ml-kem-768.h>
#include <string.h>

static const uint8_t keygen_seed[MLKEM768_KEYGEN_SEED_BYTES] = {
    0x9f, 0x7c, 0xd3, 0x5a, 0x21, 0x88, 0xe4, 0x10, 0x6b, 0x3d, 0xf0, 0x97, 0x42, 0xae, 0x19, 0xc5,
    0x74, 0x0b, 0x56, 0xed, 0x31, 0x9a, 0xc8, 0x04, 0xbb, 0x67, 0x2e, 0xd9, 0x15, 0x80, 0xf3, 0x4c,
    0xa6, 0x2f, 0xd1, 0x58, 0x83, 0x0a, 0xbe, 0x45, 0x6c, 0x97, 0x20, 0xfa, 0x3d, 0x71, 0xc2, 0x0e,
    0x59, 0xe7, 0x34, 0x8a, 0x16, 0xbc, 0x05, 0x92, 0xdf, 0x48, 0x63, 0x2a, 0xb1, 0x7e, 0xc9, 0x00,
};

static const uint8_t encaps_seed[MLKEM768_ENCAPS_SEED_BYTES] = {
    0x4d, 0x25, 0xb6, 0x0f, 0x93, 0xe1, 0x58, 0x7a, 0xc4, 0x32, 0xdd, 0x09, 0x61, 0xaf, 0x84, 0x1c,
    0xf0, 0x6b, 0x37, 0x95, 0x22, 0xce, 0x48, 0x7f, 0xa9, 0x14, 0xd3, 0x5e, 0x80, 0xbb, 0x06, 0x71,
};

static void test_ml_kem_768_roundtrip(void **state) {
  (void)state;

  uint8_t ek[MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t dk[MLKEM768_SECRET_KEY_BYTES];
  uint8_t ct[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t ss_enc[MLKEM768_SHARED_KEY_BYTES];
  uint8_t ss_dec[MLKEM768_SHARED_KEY_BYTES];

  assert_int_equal(ml_kem_768_keygen(ek, dk, keygen_seed), 0);
  assert_int_equal(ml_kem_768_encaps(ct, ss_enc, ek, encaps_seed), 0);
  assert_int_equal(ml_kem_768_decaps(ss_dec, ct, dk), 0);
  assert_memory_equal(ss_enc, ss_dec, sizeof(ss_enc));

  ct[0] ^= 0x01;
  assert_int_equal(ml_kem_768_decaps(ss_dec, ct, dk), 0);
  assert_int_not_equal(memcmp(ss_enc, ss_dec, sizeof(ss_enc)), 0);
}

static void test_ml_kem_768_bad_args(void **state) {
  (void)state;

  uint8_t ek[MLKEM768_PUBLIC_KEY_BYTES];
  uint8_t dk[MLKEM768_SECRET_KEY_BYTES];
  uint8_t ct[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t ss[MLKEM768_SHARED_KEY_BYTES];

  assert_int_equal(ml_kem_768_keygen(NULL, dk, keygen_seed), -1);
  assert_int_equal(ml_kem_768_keygen(ek, NULL, keygen_seed), -1);
  assert_int_equal(ml_kem_768_encaps(NULL, ss, ek, encaps_seed), -1);
  assert_int_equal(ml_kem_768_encaps(ct, NULL, ek, encaps_seed), -1);
  assert_int_equal(ml_kem_768_encaps(ct, ss, NULL, encaps_seed), -1);
  assert_int_equal(ml_kem_768_decaps(NULL, ct, dk), -1);
  assert_int_equal(ml_kem_768_decaps(ss, NULL, dk), -1);
  assert_int_equal(ml_kem_768_decaps(ss, ct, NULL), -1);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ml_kem_768_roundtrip),
      cmocka_unit_test(test_ml_kem_768_bad_args),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
