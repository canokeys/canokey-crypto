cmake_minimum_required(VERSION 3.16)
project(canokey-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto implementation" ON)
option(TEST_WITH_MBEDCRYPTO "Enable cross-validation tests against mbedtls" ON)

if(USE_MBEDCRYPTO OR (ENABLE_CRYPTO_TESTS AND TEST_WITH_MBEDCRYPTO))
    if(NOT TARGET tfpsacrypto)
        add_definitions(-DUSE_MBEDCRYPTO)
        set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "")
        set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "")
        set(ENABLE_PROGRAMS OFF CACHE BOOL "")
        set(ENABLE_TESTING OFF CACHE BOOL "")
        # Patch tf-psa-crypto with Ed25519 Edwards curve support
        execute_process(
            COMMAND patch -p1 -N
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto
            INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto-ed25519.patch
            RESULT_VARIABLE PATCH_RESULT
        )
        add_definitions(-DMBEDTLS_ECP_DP_ED25519_ENABLED)
        add_subdirectory(tf-psa-crypto)
    endif()
endif()

file(GLOB SRC src/*.c)
add_library(canokey-crypto ${SRC})
if(USE_MBEDCRYPTO)
    target_link_libraries(canokey-crypto tfpsacrypto)
endif()
target_include_directories(canokey-crypto PUBLIC include)
if(USE_MBEDCRYPTO)
    target_include_directories(
        canokey-crypto
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include
    )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(ENABLE_CRYPTO_TESTS "Perform unit tests after build" OFF)
if(ENABLE_CRYPTO_TESTS)
    # for coverage
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-usage --coverage")
    endif()

    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()
endif(ENABLE_CRYPTO_TESTS)
