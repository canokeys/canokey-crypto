cmake_minimum_required(VERSION 3.7)
project(canokey-crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")

file(GLOB SRC src/*.c)
add_library(canokey-crypto ${SRC})
target_include_directories(canokey-crypto INTERFACE src)

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
