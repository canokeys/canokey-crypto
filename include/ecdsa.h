#ifndef CANOKEY_CRYPTO_SRC_ECDSA_H
#define CANOKEY_CRYPTO_SRC_ECDSA_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
  ECDSA_SECP256R1, // AKA NIST P-256
  ECDSA_SECP256K1,
} ECDSAType;

int ecdsa_sign(ECDSAType ecdsa_type, const uint8_t *priv_key,
               const uint8_t *digest, uint8_t *sig);

int ecdsa_verify(ECDSAType ecdsa_type, const uint8_t *pub_key,
                 const uint8_t *sig, const uint8_t *digest);

int ecdsa_generate(ECDSAType ecdsa_type, uint8_t *priv_key, uint8_t *pub_key);

/**
 * Convert r,s signature to ANSI X9.62 format
 *
 * @param input 64 bytes signature
 * @param output ANSI X9.62 format. The buffer should be at least 70 bytes. The
 * buffer can be identical to the input.
 * @return Length of signature
 */
size_t ecdsa_sig2ansi(const uint8_t *input, uint8_t *output);

#endif // CANOKEY_CRYPTO_SRC_ECDSA_H
