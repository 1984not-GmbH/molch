cmake_minimum_required (VERSION 2.6)

add_library(utils utils)

add_library(common common)
target_link_libraries(common utils)

set(tests hkdf-test
          diffie-hellman-test
          triple-diffie-hellman-test
          chain-key-derivation-test
          message-key-derivation-test
          root-and-chain-key-derivation-test
          initial-root-and-chain-key-derivation-test
          #message-test
          #message-manipulated-test
          #message-extract-header-test
          message-keystore-test
          ratchet-test)

foreach(test ${tests})
    add_executable(${test} ${test})
    target_link_libraries(${test} molch utils common)
    add_test(${test} "./${test}")
    if(NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
        add_test("${test}-valgrind" ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} "./${test}")
    endif(NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
endforeach(test)
