cmake_minimum_required(VERSION 3.7)
project(canokey-crypto C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

set(USE_CRYPTO_SUBMODULE ON)
add_subdirectory(mbed-crypto)

include_directories(include mbed-crypto/include)
file(GLOB SRC src/*.c)
add_library(canokey-crypto ${SRC} mbed-crypto)
target_include_directories(canokey-crypto INTERFACE include)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(ENABLE_TESTS "Perform unit tests after build" OFF)
if (ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    include_directories(src)
    add_subdirectory(test)
    enable_testing()
endif (ENABLE_TESTS)
