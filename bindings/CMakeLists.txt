option(GENERATE_LUA_BINDINGS "Enable the Lua binding for testing purposes" OFF)

if(GENERATE_LUA_BINDINGS AND (NOT APPLE))
    find_package(SWIG)
    if (NOT SWIG_FOUND)
        message(FATAL_ERROR "Swig is not installed.")
    endif()
    include(${SWIG_USE_FILE})

    find_package(Lua)
    if (NOT LUA_FOUND)
        message(FATAL_ERROR "Lua is not installed.")
    endif()
    include_directories(${LUA_INCLUDE_DIR})
    include_directories(${CMAKE_SOURCE_DIR})

    find_program(LUA_INTERPRETER NAMES lua lua53 lua5.3 lua52 lua5.2 lua51 lua5.1 luajit)

    swig_add_module(molch-interface lua molch.i)
    swig_link_libraries(molch-interface molch ${LUA_LIBRARIES})
    # Disable -Werror for lua-bindings
    list(FIND custom_compiler_flags "-Werror" werror_found)
    if (werror_found)
        target_compile_options(molch-interface PRIVATE "-Wno-error")
    endif()

    set(BINDING_FILES "${CMAKE_CURRENT_BINARY_DIR}/molch.lua")

    # copy the lua binding
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/molch.lua"
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/molch.lua" "${CMAKE_CURRENT_BINARY_DIR}/molch.lua"
        COMMENT "Copying molch.lua"
        VERBATIM)

    find_program(MKFIFO mkfifo)
    if (NOT (MKFIFO MATCHES "MKFIFO-NOTFOUND"))
        add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/base64.lua"
            COMMAND "${CMAKE_COMMAND}"
            ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/base64.lua" "${CMAKE_CURRENT_BINARY_DIR}/base64.lua"
            COMMENT "Copying base64.lua"
            VERBATIM)
        add_custom_command(
            OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/pipe.lua"
            COMMAND "${CMAKE_COMMAND}"
            ARGS -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/pipe.lua" "${CMAKE_CURRENT_BINARY_DIR}/pipe.lua"
            COMMENT "Copying pipe.lua"
            VERBATIM)

        list(APPEND BINDING_FILES "${CMAKE_CURRENT_BINARY_DIR}/base64.lua" "${CMAKE_CURRENT_BINARY_DIR}/pipe.lua")
    endif()

    add_custom_target(lua-bindings ALL SOURCES ${BINDING_FILES})

    subdirs(scenarios)
endif()
