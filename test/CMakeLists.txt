cmake_minimum_required (VERSION 2.6)

add_executable(hkdf-test hkdf-test)
target_link_libraries(hkdf-test molch utils)
add_test(hkdf-test hkdf-test)

add_executable(diffie-hellman-test diffie-hellman-test)
target_link_libraries(diffie-hellman-test molch utils)
add_test(diffie-hellman-test diffie-hellman-test)

add_executable(triple-diffie-hellman-test triple-diffie-hellman-test)
target_link_libraries(triple-diffie-hellman-test molch utils)
add_test(triple-diffie-hellman-test triple-diffie-hellman-test)

add_executable(chain-key-derivation-test chain-key-derivation-test)
target_link_libraries(chain-key-derivation-test molch utils)
add_test(chain-key-derivation-test chain-key-derivation-test)

add_executable(message-key-derivation-test message-key-derivation-test)
target_link_libraries(message-key-derivation-test molch utils)
add_test(message-key-derivation-test message-key-derivation-test)

add_executable(message-test message-test)
target_link_libraries(message-test molch utils)
add_test(message-test message-test)

add_executable(message-extract-header-test message-extract-header-test)
target_link_libraries(message-extract-header-test molch utils)
add_test(message-extract-header-test message-extract-header-test)

add_executable(message-keystore-test message-keystore-test)
target_link_libraries(message-keystore-test molch utils)
add_test(message-keystore-test message-keystore-test)
