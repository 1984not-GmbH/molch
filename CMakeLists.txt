cmake_minimum_required (VERSION 2.6)

project (molch)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lsodium")

add_library(hkdf hkdf)

add_library(utils utils)

add_library(diffie-hellman diffie-hellman)

add_executable(hkdf-test hkdf-test)
target_link_libraries(hkdf-test hkdf utils)
add_test(hkdf-test hkdf-test)

add_executable(diffie-hellman-test diffie-hellman-test)
target_link_libraries(diffie-hellman-test diffie-hellman utils)
add_test(diffie-hellman-test diffie-hellman-test)
