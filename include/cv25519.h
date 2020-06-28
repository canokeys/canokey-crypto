/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CV25519_H
#define CV25519_H

#include <stddef.h>

typedef unsigned char curve25519_key[32];

/**
 * Calculate shared_secret = private_key * public_key, the second step of X25519
 *
 * Note: X25519 spec uses little endian, but we use big endian here
 *
 * @param shared_secret Shared secret in big endian
 * @param private_key Valid private key in big endian
 * @param public_key Public key in big endian
 */
void x25519(curve25519_key shared_secret, const curve25519_key private_key,
            const curve25519_key public_key);

/**
 * Create a valid Curve25519 private key from random numbers
 *
 * @param private_key Input & output of private key in big endian
 */
void curve25519_key_from_random(curve25519_key private_key);

#endif // CV25519_H
