set(scenarios normal-conversation reordering invalid_message double-import restart fail)

add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/scenarios.lua"
    COMMAND ${CMAKE_COMMAND}
    ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/scenarios.lua" "${CMAKE_CURRENT_BINARY_DIR}/scenarios.lua"
    COMMENT "Copying scenarios.lua"
    VERBATIM)
set(SCENARIO_FILES "${CMAKE_CURRENT_BINARY_DIR}/scenarios.lua")

# copy all scenarios to the test binary dir
foreach(scenario ${scenarios})
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${scenario}"
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/${scenario}" "${CMAKE_CURRENT_BINARY_DIR}/${scenario}"
        COMMENT "Copying scenario ${scenario}"
        VERBATIM
    )
    list(APPEND SCENARIO_FILES "${CMAKE_CURRENT_BINARY_DIR}/${scenario}")
    if((NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND")) AND (NOT ("${scenario}" MATCHES "fail")))
        add_test("scenario-${scenario}" sh -c "cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/${scenario} | ${LUA_INTERPRETER}")
        set_property(TEST "scenario-${scenario}" PROPERTY FAIL_REGULAR_EXPRESSION "^${LUA_INTERPRETER}: ")
    endif()
endforeach()

# negative test
if (NOT ("${LUA_INTERPRETER}" MATCHES "LUA_INTERPRETER-NOTFOUND"))
    add_test("scenario-fail" sh -c "cat scenarios.lua ${CMAKE_CURRENT_BINARY_DIR}/fail | ${LUA_INTERPRETER}")
    set_property(TEST "scenario-fail" PROPERTY WILL_FAIL TRUE)
endif()

add_custom_target(lua-scenarios ALL SOURCES ${SCENARIO_FILES})
