add_definitions(-DTEST)

add_mocked_test(sha LINK_LIBRARIES canokey-crypto)
add_mocked_test(ecdsa LINK_LIBRARIES canokey-crypto)
add_mocked_test(aes LINK_LIBRARIES canokey-crypto)
add_mocked_test(des LINK_LIBRARIES canokey-crypto)
