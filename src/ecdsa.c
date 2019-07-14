#include "ecdsa.h"
#include "ecdsa-generic.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include <memory.h>

__attribute__((weak))
int ecdsa_sign(ECDSAType ecdsa_type, const uint8_t *priv_key,
               const uint8_t *digest, uint8_t *sig) {
  if (ecdsa_type == ECDSA_SECP256K1) {
    return ecdsa_sign_digest(&secp256k1, priv_key, digest, sig);
  } else if (ecdsa_type == ECDSA_SECP256R1) {
    return ecdsa_sign_digest(&nist256p1, priv_key, digest, sig);
  }
  return -1;
}

__attribute__((weak))
int ecdsa_verify(ECDSAType ecdsa_type, const uint8_t *pub_key,
                        const uint8_t *sig, const uint8_t *digest) {
  if (ecdsa_type == ECDSA_SECP256K1) {
    return ecdsa_verify_digest(&secp256k1, pub_key, sig, digest);
  } else if (ecdsa_type == ECDSA_SECP256R1) {
    return ecdsa_verify_digest(&nist256p1, pub_key, sig, digest);
  }
  return -1;
}

__attribute__((weak))
int ecdsa_generate(ECDSAType ecdsa_type, uint8_t *priv_key, uint8_t *pub_key) {
  if (ecdsa_type == ECDSA_SECP256K1) {
    ecdsa_generate_keypair(&secp256k1, priv_key, pub_key);
    return 0;
  } else if (ecdsa_type == ECDSA_SECP256R1) {
    ecdsa_generate_keypair(&nist256p1, priv_key, pub_key);
    return 0;
  }
  return -1;
}

size_t ecdsa_sig2ansi(const uint8_t *input, uint8_t *output) {
  size_t part1_len = (input[0] < 0x80) ? 0x20 : 0x21;
  size_t part2_len = (input[32] < 0x80) ? 0x20 : 0x21;
  memmove(output + 6 + part1_len + (part2_len - 0x20), input + 32, 32);
  memmove(output + 4 + (part1_len - 0x20), input, 32);
  output[0] = 0x30;
  output[1] = (uint8_t) (part1_len + part2_len + 4);
  output[2] = 0x02;
  output[3] = (uint8_t) part1_len;
  if (part1_len == 0x21) output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = (uint8_t) part2_len;
  if (part2_len == 0x21) output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}
