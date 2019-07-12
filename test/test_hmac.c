#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "hmac.h"

static void test_hmac_sha256(void **state) {
  uint8_t key[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t buf[32];
  uint8_t expected[] =
      {0xc0, 0xd6, 0xf7, 0xec, 0x99, 0xb6, 0xfb, 0xfe, 0xc1, 0xe0, 0xbe, 0xd5, 0xa1, 0x0d, 0xd1, 0xe5, 0xcd, 0xe7, 0xbe,
       0x11, 0x4c, 0x41, 0x71, 0x81, 0x69, 0xc7, 0xd6, 0x3e, 0x67, 0x05, 0x6d, 0x28};
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
      cmocka_unit_test(test_hmac_sha256),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}