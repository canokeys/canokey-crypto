add_definitions(-DTEST)

add_mocked_test(sha SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/sha2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/sha3.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/hmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/memzero.c
        LINK_LIBRARIES mbedcrypto)

add_mocked_test(ecdsa SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdsa.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/ecdsa-generic.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/bignum.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/nist256p1.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/secp256k1.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/rand.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/memzero.c
        LINK_LIBRARIES mbedcrypto)

add_mocked_test(aes SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/block-cipher.c
        LINK_LIBRARIES mbedcrypto)
