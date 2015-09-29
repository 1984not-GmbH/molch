cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test lib)

set(CMAKE_BUILD_TYPE Debug)

enable_testing()

#Set the linker flag for sodium
set(SECURITY_C_FLAGS "-fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security -fPIE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror ${SECURITY_C_FLAGS}")
set(SECURITY_LINK_FLAGS "-z relro -z now -pie -z noexecstack -z noexecheap")
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINKER_FLAGS} -lsodium ${SECURITY_LINK_FLAGS}")

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
