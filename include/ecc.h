#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <stddef.h>
#include <stdint.h>

#define ECC_KEY_SIZE 32
#define ECC_PUB_KEY_SIZE 64

typedef enum {
  ECC_SECP256R1, // AKA NIST P-256
  ECC_SECP256K1,
} ECC_Curve;

int ecdsa_sign(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig);

int ecdsa_verify(ECC_Curve curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);

int ecc_generate(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key);

int ecc_get_public_key(ECC_Curve curve, const uint8_t *priv_key, uint8_t *pub_key);

int ecdh_decrypt(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

/**
 * Convert r,s signature to ANSI X9.62 format
 *
 * @param input 64 bytes signature
 * @param output ANSI X9.62 format. The buffer should be at least 70 bytes.
 * The buffer can be identical to the input.
 * @return Length of signature
 */
size_t ecdsa_sig2ansi(const uint8_t *input, uint8_t *output);

#endif
