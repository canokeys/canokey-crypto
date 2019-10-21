#include "ecdsa-generic.h"
#include "nist256p1.h"
#include "secp256k1.h"
#include <ecc.h>
#include <memzero.h>
#include <string.h>

__attribute__((weak)) int ecdsa_sign(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  if (ecdsa_sign_digest(cur, priv_key, digest, sig) < 0) return -1;
  return 0;
}

__attribute__((weak)) int ecdsa_verify(ECC_Curve curve, const uint8_t *pub_key, const uint8_t *sig,
                                       const uint8_t *digest) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  return ecdsa_verify_digest(cur, pub_key, sig, digest);
}

__attribute__((weak)) int ecc_generate(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  ecdsa_generate_keypair(cur, priv_key, pub_key);
  return 0;
}

__attribute__((weak)) int ecc_verify_private_key(ECC_Curve curve, uint8_t *priv_key) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  return ecdsa_verify_prikey(cur, priv_key);
}

__attribute__((weak)) int ecc_get_public_key(ECC_Curve curve, const uint8_t *priv_key, uint8_t *pub_key) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  ecdsa_get_public_key(cur, priv_key, pub_key);
  return 0;
}

__attribute__((weak)) int ecdh_decrypt(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *receiver_pub_key,
                                       uint8_t *out) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    return -1;
  curve_point pub;
  if (!ecdsa_read_pubkey(cur, receiver_pub_key, &pub)) return -1;
  bignum256 s;
  bn_read_be(priv_key, &s);
  point_multiply(cur, &s, &pub, &pub);
  bn_write_be(&pub.x, out);
  bn_write_be(&pub.y, out + 32);
  memzero(&s, sizeof(s));
  return 0;
}

size_t ecdsa_sig2ansi(const uint8_t *input, uint8_t *output) {
  int leading_zero_len1 = 0;
  int leading_zero_len2 = 0;
  for (uint8_t i = 0; i < 32; ++i)
    if (input[i] == 0)
      ++leading_zero_len1;
    else {
      if (input[i] >= 0x80) --leading_zero_len1;
      break;
    }
  for (uint8_t i = 32; i < 64; ++i)
    if (input[i] == 0)
      ++leading_zero_len2;
    else {
      if (input[i] >= 0x80) --leading_zero_len2;
      break;
    }
  uint8_t part1_len = 0x20 - leading_zero_len1;
  uint8_t part2_len = 0x20 - leading_zero_len2;
  if (leading_zero_len1 < 0) leading_zero_len1 = 0;
  if (leading_zero_len2 < 0) leading_zero_len2 = 0;
  memmove(output + 6 + part1_len + (part2_len == 0x21 ? 1 : 0), input + 32 + leading_zero_len2, 32 - leading_zero_len2);
  memmove(output + 4 + (part1_len == 0x21 ? 1 : 0), input + leading_zero_len1, 32 - leading_zero_len1);
  output[0] = 0x30;
  output[1] = part1_len + part2_len + 4;
  output[2] = 0x02;
  output[3] = part1_len;
  if (part1_len == 0x21) output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = part2_len;
  if (part2_len == 0x21) output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}
