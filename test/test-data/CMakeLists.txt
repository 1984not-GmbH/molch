cmake_minimum_required (VERSION 2.6)

set(test-files molch-init.backup molch-init-backup.key)

# copy all test files to the test binary dir
foreach(test-file ${test-files})
    execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${test-file}" "${CMAKE_CURRENT_BINARY_DIR}/${test-file}")
endforeach()
