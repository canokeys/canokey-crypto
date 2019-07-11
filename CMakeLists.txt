cmake_minimum_required(VERSION 3.7)
project(canokey_crypto C)

set(CMAKE_C_STANDARD 11)

add_library(canokey_crypto memzero.c memzero.h sha2.c sha2.h)