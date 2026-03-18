add_mocked_test(sha LINK_LIBRARIES canokey-crypto)
add_mocked_test(ecdsa
        SOURCES bignum.c ecdsa-generic.c nist256p1.c
        LINK_LIBRARIES canokey-crypto
)
add_mocked_test(aes LINK_LIBRARIES canokey-crypto)
add_mocked_test(des LINK_LIBRARIES canokey-crypto)
add_mocked_test(25519 LINK_LIBRARIES canokey-crypto)
add_mocked_test(rsa LINK_LIBRARIES canokey-crypto)

if(TEST_WITH_MBEDCRYPTO)
    add_mocked_test(sha3_random LINK_LIBRARIES canokey-crypto tfpsacrypto)
    target_include_directories(test_sha3_random PRIVATE
        ${CMAKE_SOURCE_DIR}/tf-psa-crypto/include
        ${CMAKE_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include
    )
endif()
