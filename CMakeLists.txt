cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test lib)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lsodium -Wall -Wextra -Werror")
