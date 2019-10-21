#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <stddef.h>
#include <stdint.h>

#define ECC_KEY_SIZE 32
#define ECC_PUB_KEY_SIZE 64

typedef enum {
  ECC_SECP256R1, // a.k.a., NIST P-256
  ECC_SECP256K1,
} ECC_Curve;

/**
 * Sign the given digest
 *
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param priv_key The 32-byte private key
 * @param digest The 32-byte digest
 * @param sig The output buffer (should be 64-byte long)
 * @return 0: Success, -1: Error
 */
int ecdsa_sign(ECC_Curve curve, const uint8_t *priv_key, const uint8_t *digest, uint8_t *sig);

/**
 * Verify the given signature
 *
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param pub_key The 64-byte public key
 * @param sig The 64-byte signature
 * @param digest The 32-byte digest
 * @return 0: Success, others: Error
 */
int ecdsa_verify(ECC_Curve curve, const uint8_t *pub_key, const uint8_t *sig, const uint8_t *digest);

/**
 * Generate an EcDSA key pair
 *
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param priv_key The output buffer for the private key (should be 32-byte long)
 * @param pub_key The output buffer for the public key (should be 64-byte long)
 * @return 0: Success, -1: Error
 */
int ecc_generate(ECC_Curve curve, uint8_t *priv_key, uint8_t *pub_key);

/**
 * Verify the given private key.
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param priv_key The 32-byte private key
 * @return 1: verified, 0: not verified
 */
int ecc_verify_private_key(ECC_Curve curve, uint8_t *priv_key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param priv_key The 32-byte private key
 * @param pub_key The output buffer for the public key (should be 64-byte long)
 * @return 0: Success, -1: Error
 */
int ecc_get_public_key(ECC_Curve curve, const uint8_t *priv_key, uint8_t *pub_key);

/**
 * Compute ECDH result
 *
 * @param curve ECC_Curve, must support ECC_SECP256R1
 * @param priv_key The 32-byte private key s
 * @param receiver_pub_key The receiver's public key P
 * @param out s*P
 * @return 0: Success, -1: Error
 */
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
