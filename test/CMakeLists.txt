add_mocked_test(sha LINK_LIBRARIES canokey-crypto)
add_mocked_test(ecdsa
        SOURCES bignum.c ecdsa-generic.c nist256p1.c
        LINK_LIBRARIES canokey-crypto)
add_mocked_test(aes LINK_LIBRARIES canokey-crypto)
add_mocked_test(des LINK_LIBRARIES canokey-crypto)
add_mocked_test(25519 LINK_LIBRARIES canokey-crypto)
