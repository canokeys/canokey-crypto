#include <hmac.h>
#include <rsa.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

static void test_rsa128_get_public(void **state) {
  (void)state;
  uint8_t buf[16];
  rsa_key_t key;
  uint8_t p[] = {0xe2, 0x06, 0x9b, 0x75, 0xe1, 0x96, 0x37, 0xbd};
  uint8_t q[] = {0x99, 0x84, 0x8e, 0xe6, 0x5d, 0x6c, 0xb8, 0xf9};
  uint8_t e[] = {0, 1, 0, 1};
  uint8_t expected[16] = {0x87, 0x8a, 0xfc, 0x7c, 0xab, 0x42, 0x8c, 0x62,
                          0xb3, 0x2d, 0x97, 0x39, 0x8f, 0xe8, 0x0e, 0xd5};
  key.nbits = 128;
  memcpy(key.p, p, sizeof(p));
  memcpy(key.q, q, sizeof(q));
  memcpy(key.e, e, sizeof(e));
  rsa_get_public_key(&key, buf);
  for (int i = 0; i != 16; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

static void test_rsa128_decrypt(void **state) {
  (void)state;
  uint8_t buf[16];
  rsa_key_t key;
  uint8_t p[] = {0xe2, 0x06, 0x9b, 0x75, 0xe1, 0x96, 0x37, 0xbd};
  uint8_t q[] = {0x99, 0x84, 0x8e, 0xe6, 0x5d, 0x6c, 0xb8, 0xf9};
  uint8_t e[] = {0, 1, 0, 1};
  uint8_t cipher_text[] = {0x16, 0x36, 0x55, 0xa1, 0x43, 0xba, 0x9e, 0xea,
                           0x2e, 0xff, 0xfc, 0x67, 0x41, 0xb2, 0xe7, 0xc6};
  // ascii test
  uint8_t expected[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x9d, 0x07, 0xfd, 0x9c, 0xaf, 0xff};
  key.nbits = 128;
  memcpy(key.p, p, sizeof(p));
  memcpy(key.q, q, sizeof(q));
  memcpy(key.e, e, sizeof(e));
  rsa_private(&key, cipher_text, buf);
  for (int i = 0; i != 16; ++i) {
    assert_int_equal(buf[i], expected[i]);
  }
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_rsa128_get_public),
      cmocka_unit_test(test_rsa128_decrypt),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}