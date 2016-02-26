cmake_minimum_required (VERSION 2.6)

add_library(utils utils)
target_link_libraries(utils molch-buffer)
if (TRACING)
    target_link_libraries(utils tracing)
endif()

add_library(common common)
target_link_libraries(common utils)

add_library(packet-test-lib packet-test-lib)
target_link_libraries(packet-test-lib molch molch-buffer utils)

set(tests diffie-hellman-test
          triple-diffie-hellman-test
          key-derivation-test
          chain-key-derivation-test
          message-key-derivation-test
          root-next-header-and-chain-key-derivation-test
          initial-root-chain-and-header-key-derivation-test
          packet-get-metadata-test
          packet-decrypt-header-test
          packet-decrypt-message-test
          packet-decrypt-test
          header-test
          header-and-message-keystore-test
          ratchet-test
          ratchet-test-simple
          user-store-test
          spiced-random-test
          molch-test
          conversation-test
          conversation-packet-test
          conversation-store-test
          prekey-store-test
          master-keys-test)

foreach(test ${tests})
    add_executable(${test} ${test})
    target_link_libraries(${test} molch molch-buffer utils common packet-test-lib)
    add_test(${test} "./${test}")
    if(NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
        add_test("${test}-valgrind" ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} "./${test}")
    endif(NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND"))
endforeach(test)
