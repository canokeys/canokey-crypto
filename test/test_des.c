// SPDX-License-Identifier: Apache-2.0
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <block-cipher.h>
#include <cmocka.h>
#include <des.h>

static void test_des_ecb(void **state) {
  (void)state;

  uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t expected[] = {0xE1, 0xB2, 0x46, 0xE5, 0xA7, 0xC7, 0x4C, 0xBC};

  block_cipher_config cfg = {.mode = ECB,
                             .in = data,
                             .in_size = sizeof(data),
                             .out = data,
                             .key = key,
                             .iv = NULL,
                             .block_size = 8,
                             .encrypt = des_enc,
                             .decrypt = des_dec};
  block_cipher_enc(&cfg);
  for (int i = 0; i != 8; ++i) {
    assert_int_equal(data[i], expected[i]);
  }

  block_cipher_dec(&cfg);
  for (int i = 0; i != 8; ++i) {
    assert_int_equal(data[i], i);
  }
}

static void test_tdes_ecb(void **state) {
  (void)state;

  uint8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  uint8_t expected[] = {0x58, 0xED, 0x24, 0x8F, 0x77, 0xF6, 0xB1, 0x9E};

  block_cipher_config cfg = {.mode = ECB,
                             .in = data,
                             .in_size = sizeof(data),
                             .out = data,
                             .key = key,
                             .iv = NULL,
                             .block_size = 8,
                             .encrypt = tdes_enc,
                             .decrypt = tdes_dec};
  block_cipher_enc(&cfg);
  for (int i = 0; i != 8; ++i) {
    assert_int_equal(data[i], expected[i]);
  }

  block_cipher_dec(&cfg);
  for (int i = 0; i != 8; ++i) {
    assert_int_equal(data[i], i);
  }
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_des_ecb),
      cmocka_unit_test(test_tdes_ecb),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}