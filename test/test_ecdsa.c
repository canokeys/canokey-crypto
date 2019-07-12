#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ecdsa.h"
#include "utils.h"
#include "rand.h"

static void test_ecdsa(void **state) {
  uint8_t priv_key[32], pub_key[64];
  uint8_t digest[32], sig[64];
  random_buffer(digest, 32);
  ecdsa_generate(ECDSA_SECP256K1, priv_key, pub_key);
  printHex(priv_key, 32);
  printHex(pub_key, 64);
  ecdsa_sign(ECDSA_SECP256K1, priv_key, digest, sig);
  assert_int_equal(ecdsa_verify(ECDSA_SECP256K1, pub_key, sig, digest), 0);
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_ecdsa),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
