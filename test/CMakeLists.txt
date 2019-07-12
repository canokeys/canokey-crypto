add_mocked_test(sha2 SOURCES
        ${CMAKE_SOURCE_DIR}/src/sha2.c
        ${CMAKE_SOURCE_DIR}/src/memzero.c)
add_mocked_test(sha3 SOURCES
        ${CMAKE_SOURCE_DIR}/src/sha3.c
        ${CMAKE_SOURCE_DIR}/src/memzero.c)
add_mocked_test(hmac SOURCES
        ${CMAKE_SOURCE_DIR}/src/hmac.c
        ${CMAKE_SOURCE_DIR}/src/sha2.c
        ${CMAKE_SOURCE_DIR}/src/memzero.c)
add_mocked_test(ecdsa SOURCES
        ${CMAKE_SOURCE_DIR}/src/ecdsa.c
        ${CMAKE_SOURCE_DIR}/src/ecdsa-generic.c
        ${CMAKE_SOURCE_DIR}/src/bignum.c
        ${CMAKE_SOURCE_DIR}/src/nist256p1.c
        ${CMAKE_SOURCE_DIR}/src/secp256k1.c
        ${CMAKE_SOURCE_DIR}/src/rand.c
        ${CMAKE_SOURCE_DIR}/src/utils.c
        ${CMAKE_SOURCE_DIR}/src/memzero.c)