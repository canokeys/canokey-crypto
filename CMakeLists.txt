cmake_minimum_required(VERSION 3.7)
project(canokey_crypto C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(src)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

option(ENABLE_TESTS "Perform unit tests after build" OFF)
if (ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()
endif (ENABLE_TESTS)
