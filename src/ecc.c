#include "ecdsa-generic.h"
#include "nist256p1.h"
#include "secp256k1.h"
#include <ecc.h>
#include <memzero.h>
#include <string.h>

__attribute__((weak)) CRYPTO_RESULT ecdsa_sign(ECC_Curve curve,
                                               const uint8_t *priv_key,
                                               const uint8_t *digest,
                                               uint8_t *sig) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else if (curve == ECC_SECP256K1)
    cur = &secp256k1;
  else
    return FAILURE;
  if (ecdsa_sign_digest(cur, priv_key, digest, sig) < 0)
    return FAILURE;
  return SUCCESS;
}

__attribute__((weak)) CRYPTO_RESULT ecdsa_verify(ECC_Curve curve,
                                                 const uint8_t *pub_key,
                                                 const uint8_t *sig,
                                                 const uint8_t *digest) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else if (curve == ECC_SECP256K1)
    cur = &secp256k1;
  else
    return FAILURE;
  return ecdsa_verify_digest(cur, pub_key, sig, digest);
}

__attribute__((weak)) CRYPTO_RESULT
ecc_generate(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else if (curve == ECC_SECP256K1)
    cur = &secp256k1;
  else
    return FAILURE;
  ecdsa_generate_keypair(cur, priv_key, pub_key);
  return SUCCESS;
}

__attribute__((weak)) CRYPTO_RESULT
ecc_get_public_key(ECC_Curve curve, const uint8_t *priv_key, uint8_t *pub_key) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else if (curve == ECC_SECP256K1)
    cur = &secp256k1;
  else
    return FAILURE;
  ecdsa_get_public_key(cur, priv_key, pub_key);
  return SUCCESS;
}

__attribute__((weak)) CRYPTO_RESULT
ecdh_decrypt(ECC_Curve curve, const uint8_t *priv_key,
             const uint8_t *receiver_pub_key, uint8_t *out) {
  const ecdsa_curve *cur;
  if (curve == ECC_SECP256R1)
    cur = &nist256p1;
  else
    cur = &secp256k1;
  curve_point pub;
  if (!ecdsa_read_pubkey(cur, receiver_pub_key, &pub))
    return FAILURE;
  bignum256 s;
  bn_read_be(priv_key, &s);
  point_multiply(cur, &s, &pub, &pub);
  bn_write_be(&pub.x, out);
  bn_write_be(&pub.y, out + 32);
  memzero(&s, sizeof(s));
  return SUCCESS;
}

size_t ecdsa_sig2ansi(const uint8_t *input, uint8_t *output) {
  size_t part1_len = (input[0] < 0x80) ? 0x20 : 0x21;
  size_t part2_len = (input[32] < 0x80) ? 0x20 : 0x21;
  memmove(output + 6 + part1_len + (part2_len - 0x20), input + 32, 32);
  memmove(output + 4 + (part1_len - 0x20), input, 32);
  output[0] = 0x30;
  output[1] = (uint8_t)(part1_len + part2_len + 4);
  output[2] = 0x02;
  output[3] = (uint8_t)part1_len;
  if (part1_len == 0x21)
    output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = (uint8_t)part2_len;
  if (part2_len == 0x21)
    output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}
