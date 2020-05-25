#include "ed25519.h"
#include "rand.h"
#include "sha.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>

void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk) {
  // calc sha512 of sk
  uint8_t digest[SHA512_DIGEST_LENGTH];
  sha512_raw(sk, sizeof(ed25519_secret_key), digest);

  // normalize
  digest[0] &= 248;
  digest[31] &= 127;
  digest[31] |= 64;

  // init ed25519 group
  mbedtls_ecp_group ed25519;
  mbedtls_ecp_group_init(&ed25519);
  mbedtls_ecp_group_load(&ed25519, MBEDTLS_ECP_DP_ED25519);

  // load digest
  mbedtls_mpi s;
  mbedtls_mpi_init(&s);
  mbedtls_mpi_read_binary_le(&s, digest, 32);

  // P = s*B
  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);
  mbedtls_ecp_mul(&ed25519, &p, &s, &ed25519.G, mbedtls_rnd, NULL);

  // write result
  size_t output_len;
  mbedtls_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED,
                                 &output_len, pk, sizeof(ed25519_public_key));


  // cleanup
  mbedtls_ecp_group_free(&ed25519);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&p);
}