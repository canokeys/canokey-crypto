/* SPDX-License-Identifier: Apache-2.0 */
#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];
typedef unsigned char curve25519_key[32];

/** 
 * Calculate public key from private key
 * 
 * @param sk Input private key
 * @param pk Output public key
*/
void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);

/** 
 * Calculate Ed25519 signature of data
 * 
 * @param m Input data
 * @param mlen Length of data
 * @param sk Private key
 * @param pk Public key
 * @param rs Output signature
*/
void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk,
                  ed25519_signature rs);

/** 
 * Calculate shared_secret = private_key * public_key, the second step of X25519
 * 
 * Note: X25519 spec uses little endian, but we use big endian here
 * 
 * @param shared_secret Shared secret in big endian
 * @param private_key Valid private key in big endian
 * @param public_key Public key in big endian
*/
void x25519(curve25519_key shared_secret, const curve25519_key private_key, const curve25519_key public_key);

/**
 * Create a valid Curve25519 private key from random numbers
 * 
 * @param private_key Input & output of private key in big endian
 */
void curve25519_key_from_random(curve25519_key private_key);

#endif // ED25519_H
