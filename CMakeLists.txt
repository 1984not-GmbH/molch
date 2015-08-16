cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test lib)

set(CMAKE_BUILD_TYPE Debug)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -Wno-typedef-redefinition")
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINKER_FLAGS} -lsodium")

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
