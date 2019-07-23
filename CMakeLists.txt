cmake_minimum_required(VERSION 3.7)
project(canokey-crypto C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

set(USE_STATIC_MBEDTLS_LIBRARY ON)
set(USE_SHARED_MBEDTLS_LIBRARY OFF)
set(USE_CRYPTO_SUBMODULE ON)
add_subdirectory(mbed-crypto)

file(GLOB SRC src/*.c)
add_library(canokey-crypto ${SRC})
target_link_libraries(canokey-crypto mbedcrypto)
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
