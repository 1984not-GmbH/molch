cmake_minimum_required (VERSION 2.6)

project (molch)

enable_testing()

#Set the linker flag for sodium
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lsodium")

add_library(hkdf hkdf)

add_library(utils utils)

add_library(diffie-hellman diffie-hellman)

add_library(key-derivation key-derivation)

add_executable(hkdf-test hkdf-test)
target_link_libraries(hkdf-test hkdf utils)
add_test(hkdf-test hkdf-test)

add_executable(diffie-hellman-test diffie-hellman-test)
target_link_libraries(diffie-hellman-test diffie-hellman utils)
add_test(diffie-hellman-test diffie-hellman-test)

add_executable(triple-diffie-hellman-test triple-diffie-hellman-test)
target_link_libraries(triple-diffie-hellman-test diffie-hellman utils)
add_test(triple-diffie-hellman-test triple-diffie-hellman-test)

add_executable(chain-key-derivation-test chain-key-derivation-test)
target_link_libraries(chain-key-derivation-test key-derivation utils)
add_test(chain-key-derivation-test chain-key-derivation-test)
