cmake_minimum_required (VERSION 2.6)

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

add_executable(message-key-derivation-test message-key-derivation-test)
target_link_libraries(message-key-derivation-test key-derivation utils)
add_test(message-key-derivation-test message-key-derivation-test)
