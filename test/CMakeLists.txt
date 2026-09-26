add_mocked_test(sha LINK_LIBRARIES canokey-crypto)
add_mocked_test(ecdsa
        SOURCES bignum.c ecdsa-generic.c nist256p1.c
        LINK_LIBRARIES canokey-crypto
)
add_mocked_test(aes LINK_LIBRARIES canokey-crypto)
add_mocked_test(des LINK_LIBRARIES canokey-crypto)
add_mocked_test(25519 LINK_LIBRARIES canokey-crypto)
add_mocked_test(rsa LINK_LIBRARIES canokey-crypto)
add_mocked_test(sm2_ke LINK_LIBRARIES canokey-crypto)

if(TEST_WITH_MBEDCRYPTO)
    add_mocked_test(ml_kem_768 LINK_LIBRARIES canokey-crypto)
    add_mocked_test(sha3_random LINK_LIBRARIES canokey-crypto tfpsacrypto)
    target_include_directories(test_sha3_random PRIVATE
        ${CMAKE_SOURCE_DIR}/tf-psa-crypto/include
        ${CMAKE_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include
    )
endif()

if(USE_MBEDCRYPTO)
    add_executable(sm3-correctness sm3_correctness.c)
    target_link_libraries(sm3-correctness PRIVATE canokey-crypto)
    add_test(NAME sm3-correctness COMMAND sm3-correctness)
endif()

if(NOT USE_PLATFORM_KECCAK_P1600)
    add_executable(keccak-bytes-correctness keccak_bytes_correctness.c)
    target_link_libraries(keccak-bytes-correctness PRIVATE canokey-crypto)
    add_test(NAME keccak-bytes-correctness COMMAND keccak-bytes-correctness)
endif()
