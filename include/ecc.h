/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  ECC_SECP256R1,
  ECC_SECP256K1,
  ECC_SECP384R1,
  ECC_SM2,
} ECC_Curve;

/**
 * Generate an ECDSA key pair
 *
 * @param curve     ECC_Curve
 * @param priv_key  The output buffer for the private key
 * @param pub_key   The output buffer for the public key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key);

/**
 * Generate an ECDSA key pair from the seed
 *
 * @param curve     ECC_Curve
 * @param priv_key  The output buffer for the private key
 * @param pub_key   The output buffer for the public key
 * @param seed      The seed for generating the key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate_from_seed(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key, uint8_t *seed);

/**
 * Sign the given digest
 *
 * @param curve     ECC_Curve
 * @param priv_key  The private key
 * @param digest    The digest
 * @param sig       The output buffer
 *
 * @return 0: Success, -1: Error
 */
int ecdsa_sign(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig);

/**
 * Verify the given signature
 *
 * @param curve    ECC_Curve
 * @param pub_key  The 64-byte public key
 * @param sig      The 64-byte signature
 * @param digest   The 32-byte digest
 *
 * @return 0: Success, others: Error
 */
int ecdsa_verify(ECC_Curve curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);

/**
 * Verify the given private key.
 *
 * @param curve     ECC_Curve
 * @param priv_key  The private key
 *
 * @return 1: verified, 0: not verified
 */
int ecc_verify_private_key(ECC_Curve curve, uint8_t *priv_key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param curve     ECC_Curve
 * @param priv_key  The private key
 * @param pub_key   The output buffer for the public key
 *
 * @return 0: Success, -1: Error
 */
int ecc_get_public_key(ECC_Curve curve, const uint8_t *priv_key, uint8_t *pub_key);

/**
 * Compute ECDH result
 *
 * @param curve             ECC_Curve
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int ecdh_decrypt(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

/**
 * Convert r,s signature to ANSI X9.62 format
 *
 * @param key_len Length of the key
 * @param input   The original signature
 * @param output  ANSI X9.62 format. The buffer should be at least 2 * key_size + 6 bytes. The buffer can be identical
 * to the input.
 *
 * @return Length of signature
 */
size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output);

#endif
