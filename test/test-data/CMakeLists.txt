cmake_minimum_required (VERSION 2.6)

set(test-files molch-init.backup molch-init-backup.key)

# copy all test files to the test binary dir
foreach(test-file ${test-files})
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${test-file}"
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${test-file}" "${CMAKE_CURRENT_BINARY_DIR}/${test-file}"
        COMMENT "Copying ${test-file}"
        VERBATIM)
    list(APPEND test-data-sources "${CMAKE_CURRENT_BINARY_DIR}/${test-file}")
endforeach()

add_custom_target(test-data ALL SOURCES ${test-data-sources})
