/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <algo.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_EC_PRIVATE_KEY 66
#define MAX_EC_PUBLIC_KEY 132

typedef struct {
  uint8_t pri[MAX_EC_PRIVATE_KEY];
  uint8_t pub[MAX_EC_PUBLIC_KEY];
} ecc_key_t;

/**
 * Generate an ECDSA key pair
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate(key_type_t type, ecc_key_t *key);

/**
 * Generate an ECDSA key pair from the seed
 *
 * @param type      ECC algorithm
 * @param seed      The seed for generating the key
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate_from_seed(key_type_t type, uint8_t *seed, ecc_key_t *key);

/**
 * Verify the given private key.
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 1: verified, 0: not verified
 */
int ecc_verify_private_key(key_type_t type, ecc_key_t *key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 0: Success, -1: Error
 */
int ecc_complete_key(key_type_t type, ecc_key_t *key);

/**
 * Sign the given digest
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 * @param digest    The digest
 * @param sig       The output buffer
 *
 * @return 0: Success, -1: Error
 */
int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *digest, uint8_t *sig);

/**
 * Verify the given signature
 *
 * @param type     ECC algorithm
 * @param key      Pointer to the key
 * @param sig      The signature
 * @param digest   The digest
 *
 * @return 0: Success, others: Error
 */
int ecc_verify(key_type_t type, const ecc_key_t *key, const uint8_t *sig, const uint8_t *digest);

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

/**
 * Compute ECDH result
 *
 * @param type              ECC algorithm
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

#endif
