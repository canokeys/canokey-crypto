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

  // preprocessing
  curve25519_key e;
  curve25519_key b;
  size_t i;

  // swap endianness
  for (i = 0; i < 32; ++i) {
    e[i] = secret[31 - i];
    b[i] = basepoint[31 - i];
  }
  e[31] &= 0xf8;
  e[0] &= 0x7f;
  e[0] |= 0x40;

  // init
  mbedtls_ecp_point_init(&base);
  mbedtls_ecp_point_init(&public);
  mbedtls_ecp_group_init(&cv25519);
  mbedtls_mpi_init(&sk);

  // load group
  mbedtls_ecp_group_load(&cv25519, MBEDTLS_ECP_DP_CURVE25519);

  // read base point
  mbedtls_mpi_read_binary(&base.X, b, 32);
  mbedtls_mpi_free(&base.Y);
  mbedtls_mpi_lset(&base.Z, 1);

  // read secret
  mbedtls_mpi_read_binary(&sk, e, 32);

  // multiple scalar
  curve25519_key res;
  mbedtls_ecp_mul(&cv25519, &public, &sk, &base, mbedtls_rnd, NULL);

  // write result
  size_t output_len;
  mbedtls_mpi_write_binary(&public.X, res, 32);

  // swap endianness
  for (i = 0; i < 32; ++i) {
    mypublic[i] = res[31 - i];
  }

  mbedtls_ecp_point_free(&base);
  mbedtls_ecp_point_free(&public);
  mbedtls_ecp_group_free(&cv25519);
  mbedtls_mpi_free(&base.Y);
}