cmake_minimum_required (VERSION 2.6)

project (molch C)

subdirs(test lib buffer mcJSON bindings)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

enable_testing()

option(TRACING "Enable tracing." OFF)
if (TRACING)
    message("TRACING ENABLED")
    add_definitions(-DTRACING)
    add_library(tracing "test/tracing")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finstrument-functions -finstrument-functions-exclude-function-list=printf,dladdr,putchar")
    set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -ldl")
endif()

#check if running debug build
if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    if ("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
        set(SECURITY_C_FLAGS "-O0")
    else()
        set(SECURITY_C_FLAGS "-Og")
    endif()
else()
    if(APPLE)
        set(SECURITY_C_FLAGS "-O1 -Wformat -Wformat-security")
        #TODO: Find secure Linker flags that work on Mac OS X
    else()
        set(SECURITY_C_FLAGS "-fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security")
        set(SECURITY_LINK_FLAGS "-z relro -z now -z noexecstack -z noexecheap -pie")
    endif()
endif()

find_package(Sodium REQUIRED)
find_package(Protobuf-C REQUIRED)
find_package(Protoc-C REQUIRED)

include_directories(${SODIUM_INCLUDE_DIR} ${PROTOBUFC_INCLUDE_DIR})
SET(libs ${libs} ${SODIUM_LIBRARY} ${PROTOBUFC_LIBRARY})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror -fPIC ${SECURITY_C_FLAGS}")
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} ${SECURITY_LINK_FLAGS}")

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")

if("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")
    set(MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
endif("${DISABLE_MEMORYCHECK_COMMAND}" MATCHES "TRUE")

#Doxygen
option(GENERATE_DOC "Generate documentation with Doxygen." OFF)

if (GENERATE_DOC)
    find_package(Doxygen)
    if (NOT DOXYGEN_FOUND)
        message(FATAL_ERROR "Doxygen wasn't found.")
    endif()

    if (NOT DOXYGEN_DOT_FOUND)
        message(FATAL_ERROR "Graphviz' 'dot' wasn't found.")
    endif()

    execute_process(COMMAND ${DOXYGEN_EXECUTABLE}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
