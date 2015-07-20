cmake_minimum_required (VERSION 2.6)

project (molch)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lsodium")

add_library(hkdf hkdf)

add_library(utils utils)

add_executable(hkdf-test hkdf-test)
target_link_libraries(hkdf-test hkdf utils)
add_test(hkdf-test hkdf-test)
