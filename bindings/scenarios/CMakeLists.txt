set(scenarios normal-conversation)

execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/scenarios.lua" "${CMAKE_CURRENT_BINARY_DIR}/scenarios.lua")

# copy all scenarios to the test binary dir
foreach(scenario ${scenarios})
    execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${scenario}" "${CMAKE_CURRENT_BINARY_DIR}/${scenario}")
    if(NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND"))
        add_test("scenario-${scenario}" sh -c "cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/${scenario} | ${LUA_INTERPRETER}")
        set_property(TEST "scenario-${scenario}" PROPERTY FAIL_REGULAR_EXPRESSION "^${LUA_INTERPRETER}: ")
    endif()
endforeach()

# negative test
execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/fail" "${CMAKE_CURRENT_BINARY_DIR}/fail")
if (NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND"))
    add_test("scenario-fail" sh -c "cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/fail | ${LUA_INTERPRETER}")
    set_property(TEST "scenario-fail" PROPERTY WILL_FAIL TRUE)
endif()
