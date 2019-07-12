cmake_minimum_required(VERSION 3.7)
project(canokey_crypto C)
set(CMAKE_C_STANDARD 11)
add_definitions(-DTEST)
add_subdirectory(src)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")

find_package(CMocka CONFIG REQUIRED)
include(AddCMockaTest)
include(AddMockedTest)
add_subdirectory(test)
enable_testing()