cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test lib)

set(CMAKE_BUILD_TYPE Debug)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-typedef-redefinition")
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINKER_FLAGS} -lsodium")
