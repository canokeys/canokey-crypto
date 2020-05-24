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
void x25519(curve25519_key mypublic, const curve25519_key secret, const curve25519_key basepoint);

#endif // ED25519_H
