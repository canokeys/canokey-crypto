cmake_minimum_required(VERSION 3.7)
project(canokey-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto library" ON)

if (USE_MBEDCRYPTO)
    add_definitions(-DUSE_MBEDCRYPTO)
    set(USE_STATIC_MBEDTLS_LIBRARY ON)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF)
    set(USE_CRYPTO_SUBMODULE ON)
    set(ENABLE_TESTING OFF) # disable mbedtls tests
    add_subdirectory(mbed-crypto)
endif (USE_MBEDCRYPTO)

file(GLOB SRC src/*.c)
add_library(canokey-crypto ${SRC})
if (USE_MBEDCRYPTO)
    target_link_libraries(canokey-crypto mbedcrypto)
endif (USE_MBEDCRYPTO)
target_include_directories(canokey-crypto PUBLIC include)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(ENABLE_TESTS "Perform unit tests after build" OFF)
if (ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()
endif (ENABLE_TESTS)
