cmake_minimum_required (VERSION 2.6)

add_executable(crashtest-store crashtest-store)
target_link_libraries(crashtest-store molch common utils)

add_executable(crashtest-node crashtest-node)
target_link_libraries(crashtest-node molch common utils)
