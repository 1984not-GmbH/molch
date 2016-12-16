add_library(molch-buffer buffer)
target_link_libraries(molch-buffer ${libs})

#test
add_executable(buffer-test buffer-test)
target_link_libraries(buffer-test molch-buffer)
add_test(buffer-test buffer-test)
if((NOT APPLE) AND (NOT ("${MEMORYCHECK_COMMAND}" MATCHES "MEMORYCHECK_COMMAND-NOTFOUND")))
    add_test("buffer-test-valgrind" ${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS} "./buffer-test")
endif()
