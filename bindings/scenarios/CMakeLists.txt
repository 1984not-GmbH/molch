set(scenarios normal-conversation)

find_program(LUA_INTERPRETER NAMES lua lua53 lua5.3 lua52 lua5.2 lua51 lua5.1 luajit)

# copy all scenarios to the test binary dir
foreach(scenario ${scenarios})
    execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${scenario}" "${CMAKE_CURRENT_BINARY_DIR}/${scenario}")
    if(NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND"))
        add_test("scenario-${scenario}" sh -c "cd ..; cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/${scenario} | ${LUA_INTERPRETER}")
        set_property(TEST "scenario-${scenario}" PROPERTY FAIL_REGULAR_EXPRESSION "^${LUA_INTERPRETER}: ")
    endif()
endforeach()

# negative test
execute_process(COMMAND cmake -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/fail" "${CMAKE_CURRENT_BINARY_DIR}/fail")
if (NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND"))
    add_test("scenario-fail" sh -c "cd ..; cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/fail | ${LUA_INTERPRETER}")
    set_property(TEST "scenario-fail" PROPERTY WILL_FAIL TRUE)
endif()
