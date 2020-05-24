cmake_minimum_required(VERSION 3.7)
project(canokey-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto library" ON)

if (USE_MBEDCRYPTO)
    add_definitions(-DUSE_MBEDCRYPTO)
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "")
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
    set(USE_CRYPTO_SUBMODULE ON CACHE BOOL "")
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    set(ENABLE_TESTING OFF CACHE BOOL "") # disable mbedtls tests
    add_subdirectory(mbedtls)
endif (USE_MBEDCRYPTO)

file(GLOB SRC src/*.c ed25519-donna/*.c)
add_library(canokey-crypto ${SRC})
if (USE_MBEDCRYPTO)
    target_link_libraries(canokey-crypto mbedcrypto)
endif (USE_MBEDCRYPTO)
target_include_directories(canokey-crypto PUBLIC include)
target_include_directories(canokey-crypto PRIVATE mbedtls/include)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(ENABLE_CRYPTO_TESTS "Perform unit tests after build" ON)
#if (ENABLE_CRYPTO_TESTS)
    # for coverage
    if (CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-usage --coverage")
    endif()

    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()
#endif (ENABLE_CRYPTO_TESTS)
