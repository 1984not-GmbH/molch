cmake_minimum_required (VERSION 2.6)

include_directories("${CMAKE_CURRENT_BINARY_DIR}/../lib/protobuf")
option(RUN_TESTS "Generate the tests." OFF)

if (RUN_TESTS)
    add_subdirectory(test-data)

    add_library(utils utils)

    add_library(common common)
    target_link_libraries(common utils)

    add_library(packet-test-lib packet-test-lib)
    target_link_libraries(packet-test-lib molch utils)

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
              master-keys-test
              endianness-test
              return-status-test
              molch-init-test
              alignment-test
              zeroed_malloc-test
              buffer-test
    )

    foreach(test ${tests})
        add_executable(${test} ${test})
        target_link_libraries(${test} molch utils common packet-test-lib)
        add_test(${test} "./${test}")
        if((NOT APPLE) AND (NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")))
            add_test("${test}-valgrind" ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} "./${test}")
        endif()
    endforeach(test)
endif()
