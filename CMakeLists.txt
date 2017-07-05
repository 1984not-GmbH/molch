cmake_minimum_required (VERSION 2.6)

project (molch C)

subdirs(test lib bindings)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

enable_testing()

#Setup compiler flags
list(APPEND custom_compiler_flags
    -std=c99
    -pedantic
    -Wall
    -Wextra
    -Werror
    -Wstrict-prototypes
    -Wwrite-strings
    -Wshadow
    -Winit-self
    -Wcast-align
    -Wformat=2
    -Wmissing-prototypes
    -Wstrict-overflow=2
    -Wcast-qual
    -Wundef
    -Wswitch-default
    -Wconversion
    -fstack-protector-strong
    -Wcomma
    -Wdouble-promotion
    -Wparentheses
    -fPIC
    -Wunused-macros
    -Wmissing-variable-declarations
    )

if(NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    list(APPEND custom_compiler_flags
        -O2
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=2)
else()
    list(APPEND custom_compiler_flags -O0 -Og)
endif()

# apply custom compiler flags
include(CheckCCompilerFlag)
foreach(compiler_flag ${custom_compiler_flags})
    #remove problematic characters
    string(REGEX REPLACE "[^a-zA-Z0-9]" "" current_variable ${compiler_flag})

    CHECK_C_COMPILER_FLAG(${compiler_flag} "FLAG_SUPPORTED_${current_variable}")
    if (FLAG_SUPPORTED_${current_variable})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${compiler_flag}")
    endif()
endforeach()

#Set linker flags
if(NOT APPLE)
    set(SECURITY_LINK_FLAGS "-z relro -z now -z noexecstack -z noexecheap -pie")
endif()
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} ${SECURITY_LINK_FLAGS}")

find_package(sodium 1.0.12 REQUIRED)
find_package(Protobuf-C REQUIRED)
find_package(Protoc-C REQUIRED)

include_directories(${SODIUM_INCLUDE_DIR} ${PROTOBUFC_INCLUDE_DIR})
SET(libs ${libs} sodium ${PROTOBUFC_LIBRARY})


find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --trace-children=yes --leak-check=full --error-exitcode=10)

if("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "valgrind not found")
endif("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")

# check if protoc-c works with valgrind (check for weird error on ArchlinuxARM on ARMv7 that breaks CI)
if (NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
    execute_process(
        COMMAND ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} ${PROTOC_C_EXECUTABLE}
        RESULT_VARIABLE VALGRIND_ERROR
        OUTPUT_QUIET
        ERROR_QUIET)
    if ("${VALGRIND_ERROR}" MATCHES "10")
        set(MEMORYCHECK_COMMAND "MEMORYCHECK_COMMAND-NOTFOUND")
        message(WARNING "valgrind disabled")
    endif()
endif()

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

