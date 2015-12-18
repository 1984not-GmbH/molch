cmake_minimum_required (VERSION 2.6)

project (molch)

subdirs(test lib buffer mcJSON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

enable_testing()

#check if running debug build
if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    if ("${CMAKE_C_COMPILER}" MATCHES "clang")
        set(SECURITY_C_FLAGS "-O0")
    else()
        set(SECURITY_C_FLAGS "-Og")
    endif()
else()
    if(APPLE)
        set(SECURITY_C_FLAGS "-O1 -Wformat -Wformat-security -fPIE")
        #TODO: Find secure Linker flags that work on Mac OS X
    else()
        set(SECURITY_C_FLAGS "-fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security -fPIE")
        set(SECURITY_LINK_FLAGS "-z relro -z now -pie -z noexecstack -z noexecheap")
    endif()
endif()

find_package(Sodium REQUIRED)

include_directories(${SODIUM_INCLUDE_DIR})
SET(libs ${libs} ${SODIUM_LIBRARY})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror ${SECURITY_C_FLAGS}")
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} ${SECURITY_LINK_FLAGS}")

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")

if("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")
    set(MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
endif("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")
