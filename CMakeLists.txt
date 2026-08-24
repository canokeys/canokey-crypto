cmake_minimum_required(VERSION 3.16)
project(canokey-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto implementation" ON)
option(TEST_WITH_MBEDCRYPTO "Enable cross-validation tests against mbedtls" ON)
option(USE_PLATFORM_KECCAK_P1600 "Use a platform-provided Keccak-p1600 implementation" OFF)

if(USE_MBEDCRYPTO OR (ENABLE_CRYPTO_TESTS AND TEST_WITH_MBEDCRYPTO))
    set(USE_STATIC_TF_PSA_CRYPTO_LIBRARY ON CACHE BOOL "")
    set(USE_SHARED_TF_PSA_CRYPTO_LIBRARY OFF CACHE BOOL "")
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    set(ENABLE_TESTING OFF CACHE BOOL "")
    # Patch tf-psa-crypto with Ed25519 Edwards curve support. Check both
    # directions first so repeated CMake configuration does not create .rej
    # files for an already-applied patch.
    execute_process(
        COMMAND patch -p1 -s -N -V never --dry-run
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto
        INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto-ed25519.patch
        RESULT_VARIABLE ED25519_PATCH_CAN_APPLY
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(ED25519_PATCH_CAN_APPLY EQUAL 0)
        execute_process(
            COMMAND patch -p1 -s -N -V never
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto
            INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto-ed25519.patch
            RESULT_VARIABLE ED25519_PATCH_RESULT
        )
        if(NOT ED25519_PATCH_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to apply tf-psa-crypto Ed25519 patch")
        endif()
    else()
        execute_process(
            COMMAND patch -p1 -s -R -V never --dry-run
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto
            INPUT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto-ed25519.patch
            RESULT_VARIABLE ED25519_PATCH_IS_APPLIED
            OUTPUT_QUIET
            ERROR_QUIET
        )
        if(NOT ED25519_PATCH_IS_APPLIED EQUAL 0)
            message(FATAL_ERROR "tf-psa-crypto Ed25519 patch does not apply cleanly")
        endif()
    endif()
    add_definitions(-DMBEDTLS_ECP_DP_ED25519_ENABLED)
    add_subdirectory(tf-psa-crypto)
endif()

file(GLOB SRC src/*.c)
if(USE_PLATFORM_KECCAK_P1600)
    list(FILTER SRC EXCLUDE REGEX "/keccak_p1600\\.c$")
endif()
add_library(canokey-crypto STATIC ${SRC})
if(USE_MBEDCRYPTO)
    target_compile_definitions(canokey-crypto PUBLIC USE_MBEDCRYPTO)
    target_link_libraries(canokey-crypto tfpsacrypto)
    target_include_directories(
        canokey-crypto
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto/include
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tf-psa-crypto/drivers/pqcp/mldsa-native/mldsa
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mlkem-native/mlkem
    )
endif()
target_include_directories(canokey-crypto PUBLIC include)

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
