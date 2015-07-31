cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lsodium -Wall -Wextra -Werror")

add_library(hkdf hkdf)

add_library(utils utils)

add_library(diffie-hellman diffie-hellman)

add_library(key-derivation key-derivation)

add_library(message message)

add_library(message-keystore message-keystore)
