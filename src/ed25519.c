#include "ed25519.h"
#include "rand.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>

void x25519(curve25519_key mypublic, const curve25519_key secret,
                           const curve25519_key basepoint) {
  mbedtls_ecp_point base;
  mbedtls_ecp_point public;
  mbedtls_ecp_group cv25519;
  mbedtls_mpi sk;

  // init
  mbedtls_ecp_point_init(&base);
  mbedtls_ecp_point_init(&public);
  mbedtls_ecp_group_init(&cv25519);
  mbedtls_mpi_init(&sk);

  // load group
  mbedtls_ecp_group_load(&cv25519, MBEDTLS_ECP_DP_CURVE25519);

  // read base point
  mbedtls_mpi_read_binary(&base.X, basepoint, 32);
  mbedtls_mpi_free(&base.Y);
  mbedtls_mpi_lset(&base.Z, 1);

  // read secret
  mbedtls_mpi_read_binary(&sk, secret, 32);

  // multiple scalar
  mbedtls_ecp_mul(&cv25519, &public, &sk, &base, mbedtls_rnd, NULL);

  // write result
  mbedtls_mpi_write_binary(&public.X, mypublic, 32);

  mbedtls_ecp_point_free(&base);
  mbedtls_ecp_point_free(&public);
  mbedtls_ecp_group_free(&cv25519);
  mbedtls_mpi_free(&sk);
}


void curve25519_key_from_random(curve25519_key private_key) {
  private_key[31] &= 0xf8;
  private_key[0] &= 0x7f;
  private_key[0] |= 0x40;
}