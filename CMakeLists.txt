cmake_minimum_required (VERSION 2.8.12)

project (molch C CXX)

subdirs(test lib bindings)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

enable_testing()

#Setup compiler flags
list(APPEND custom_compiler_flag_candidates
    -std=c++14
    -pedantic
    -Wall
    -Wextra
    -Werror
    -Wwrite-strings
    -Winit-self
    -Wformat=2
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
    -Wchkp
    -Wnull-dereference
    -Wimplicit-fallthrough
    -Wunused-parameter
    -Wstrict-aliasing=1
    -Walloc-zero
    -Walloca
    -Wduplicated-branches
    -Wduplicated-cond
    -Wfloat-equal
    -Wtrampolines
    -Wunsafe-loop-optimizations
    -Wredundant-decls
    -Wlogical-op
    #C++ options
    -Wnoexcept
    -Wstrict-null-sentinel
    -Wold-style-cast
    -Woverloaded-virtual
    -Wsign-promo
    -Wmultiple-inheritance
    -Wvirtual-inheritance
    -Wuninitialized
    -Wsuggest-final-types
    -Wsuggest-final-methods
    -Wsuggest-override
    -Wc++1z-compat
    -Wconditionally-supported
    -Wzero-as-null-pointer-constant
    )

if(NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    list(APPEND custom_compiler_flag_candidates
        -O2
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=2)
else()
    list(APPEND custom_compiler_flag_candidates -O0 -Og)
endif()

# apply custom compiler flags
include(CheckCXXCompilerFlag)
foreach(compiler_flag ${custom_compiler_flag_candidates})
    #remove problematic characters
    string(REGEX REPLACE "[^a-zA-Z0-9]" "" current_variable ${compiler_flag})

    CHECK_CXX_COMPILER_FLAG(${compiler_flag} "FLAG_SUPPORTED_${current_variable}")
    if (FLAG_SUPPORTED_${current_variable})
        set(custom_compiler_flags "${custom_compiler_flags} ${compiler_flag}")
    endif()
endforeach()

set(CMAKE_C_FLAGS "-fPIC ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${custom_compiler_flags} ${CMAKE_CXX_FLAGS}")

#Set linker flags
if(NOT APPLE)
    set(SECURITY_LINK_FLAGS "-z relro -z now -z noexecstack -z noexecheap -pie")
endif()
set(CMAKE_CXX_LINK_FLAGS "${SECURITY_LINK_FLAGS} ${CMAKE_CXX_LINK_FLAGS}")
set(CMAKE_C_LINK_FLAGS "${SECURITY_LINK_FLAGS} ${CMAKE_C_LINK_FLAGS}")

find_package(sodium 1.0.13 REQUIRED)
find_package(Protobuf-C REQUIRED)
find_package(Protoc-C REQUIRED)

include_directories(${SODIUM_INCLUDE_DIR} ${PROTOBUFC_INCLUDE_DIR})
SET(libs ${libs} sodium ${PROTOBUFC_LIBRARY})


find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS --suppressions=${CMAKE_CURRENT_SOURCE_DIR}/valgrind.supp --trace-children=yes --leak-check=full --error-exitcode=10)

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

