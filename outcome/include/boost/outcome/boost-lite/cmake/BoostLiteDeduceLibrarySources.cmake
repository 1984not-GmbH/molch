# Deduces a set of includes and sources for ${PROJECT_NAME}
# 
# Inputs:
#  *      PROJECT_NAME: The name of the project
#  * PROJECT_NAMESPACE: Any namespace for the project
#  * Directory structure from ${CMAKE_CURRENT_SOURCE_DIR} is assumed to be:
#    * include/${PROJECT_PATH}
#    * src
#    * test
#    Files matched are *.h, *.hpp, *.ipp, *.c, *.cpp *.cxx
#    Files excluded are anything with a .boostish file in its root
# 
# Outputs:
#  *                   PROJECT_DIR: PROJECT_NAMESPACE with any :: replaced with a / followed by PROJECT_NAME
#  *         PROJECT_IS_DEPENDENCY: ON if this this project is a dependency of a higher level project
#
# Cached outputs:
#  *          ${PROJECT_NAME}_PATH: ${CMAKE_CURRENT_SOURCE_DIR}
#  *     ${PROJECT_NAME}_INTERFACE: The master interface PCHable header file ${PROJECT_DIR}/${PROJECT_NAME}.hpp, plus any sources which need to be compiled into any consumers
#  *       ${PROJECT_NAME}_HEADERS: Any header files found in include
#  *       ${PROJECT_NAME}_SOURCES: Any source files found in src
#  *         ${PROJECT_NAME}_TESTS: Any source files found in test
#  *   ${PROJECT_NAME}_HEADERS_MD5: The MD5 of the results of 'find . -type f -printf "%t\t%s\t%p\n"' (POSIX) or 'dir /a-d /s' (Windows) for include
#  *   ${PROJECT_NAME}_SOURCES_MD5: The MD5 of the results of 'find . -type f -printf "%t\t%s\t%p\n"' (POSIX) or 'dir /a-d /s' (Windows) for src
#  *     ${PROJECT_NAME}_TESTS_MD5: The MD5 of the results of 'find . -type f -printf "%t\t%s\t%p\n"' (POSIX) or 'dir /a-d /s' (Windows) for test

if(DEFINED PROJECT_NAMESPACE)
  string(REPLACE "::" "/" PROJECT_DIR ${PROJECT_NAMESPACE})
else()
  set(PROJECT_DIR)
endif()
set(PROJECT_DIR ${PROJECT_DIR}${PROJECT_NAME})
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(PROJECT_IS_DEPENDENCY OFF)
else()
  set(PROJECT_IS_DEPENDENCY ON)
endif()

# Only go to the expense of recalculating this stuff if needed
if(${PROJECT_NAME}_HEADERS)
  indented_message(STATUS "Reusing cached scan of project ${PROJECT_NAME} ...")
else()
  include(BoostLiteUtils)
  indented_message(STATUS "Cached scan of project ${PROJECT_NAME} not found! Starting scan ...")
  # TODO: Is this the same as ${PROJECT_NAME}_SOURCE_DIR and therefore is redundant?
  set(${PROJECT_NAME}_PATH "${CMAKE_CURRENT_SOURCE_DIR}"
    CACHE PATH "The path to the base of the ${PROJECT_NAME} project")
  if(NOT ${PROJECT_NAME}_INTERFACE_DISABLED)
    set(${PROJECT_NAME}_INTERFACE "${PROJECT_DIR}/${PROJECT_NAME}.hpp")
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/${${PROJECT_NAME}_INTERFACE}")
      indented_message(FATAL_ERROR "FATAL: No master interface header file found at include/${${PROJECT_NAME}_INTERFACE}. "
                          "You need a master interface header file at that location if you are to make available "
                          "your library as a C++ Module or as a precompiled header. If your library can never "
                          "support a master interface header file, set ${PROJECT_NAME}_INTERFACE_DISABLED to ON."
      )
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_DIR}/${PROJECT_NAME}.ixx")
      set(${PROJECT_NAME}_INTERFACE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/include/${PROJECT_DIR}/${PROJECT_NAME}.ixx")
    endif()
  endif()
  indented_message(STATUS "  Recursively scanning ${CMAKE_CURRENT_SOURCE_DIR}/include for header files ...")
  # cmake glob is unfortunately very slow on deep directory hierarchies, so we glob
  # recursively everything we need at once and extract out from that giant list what we need
  file(GLOB_RECURSE ${PROJECT_NAME}_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
       "${CMAKE_CURRENT_SOURCE_DIR}/include/.boostish"
       "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
       "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
       "${CMAKE_CURRENT_SOURCE_DIR}/include/*.ipp"
       "${CMAKE_CURRENT_SOURCE_DIR}/include/*.natvis"
       )
  set(${PROJECT_NAME}_INTERFACE_SOURCES ${${PROJECT_NAME}_HEADERS})
  set(${PROJECT_NAME}_HEADERS_FILTER ${${PROJECT_NAME}_HEADERS})
  list_filter(${PROJECT_NAME}_HEADERS EXCLUDE REGEX "\\.boostish$")
  list_filter(${PROJECT_NAME}_INTERFACE_SOURCES INCLUDE REGEX "\\.natvis$")
  list_filter(${PROJECT_NAME}_HEADERS_FILTER INCLUDE REGEX "\\.boostish$")  
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src)
    indented_message(STATUS "  Recursively scanning ${CMAKE_CURRENT_SOURCE_DIR}/src for header and source files ...")
    file(GLOB_RECURSE ${PROJECT_NAME}_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/.boostish"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
         "${CMAKE_CURRENT_SOURCE_DIR}/src/*.ipp"
         )
    set(${PROJECT_NAME}_SOURCES_FILTER ${${PROJECT_NAME}_SOURCES})
    list_filter(${PROJECT_NAME}_SOURCES EXCLUDE REGEX "\\.boostish$")
    list_filter(${PROJECT_NAME}_SOURCES_FILTER INCLUDE REGEX "\\.boostish$")
  endif()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test)
    indented_message(STATUS "  Recursively scanning ${CMAKE_CURRENT_SOURCE_DIR}/test for header and source files ...")
    file(GLOB_RECURSE ${PROJECT_NAME}_TESTS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/.boostish"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.h"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.hpp"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.c"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.cxx"
         "${CMAKE_CURRENT_SOURCE_DIR}/test/*.ipp"
         )
    set(${PROJECT_NAME}_TESTS_FILTER ${${PROJECT_NAME}_TESTS})
    list_filter(${PROJECT_NAME}_TESTS EXCLUDE REGEX "\\.boostish$")
    list_filter(${PROJECT_NAME}_TESTS_FILTER INCLUDE REGEX "\\.boostish$")
  endif()

  # Prune any items with a .boostish in their root directory
  function(prune_boostish_libraries boostishlist fileslist)
    if(${boostishlist})
      # As an optimisation for deep nested trees of boostish libraries,
      # use the boostishlist to prune itself first
      set(boostishlist_)
      foreach(boostish ${${boostishlist}})
        string(LENGTH "${boostish}" len)
        math(EXPR len "${len} - 9")
        string(SUBSTRING "${boostish}" 0 ${len} boostish_)
        escape_string_into_regex(boostish_ "${boostish_}")
        list(APPEND boostishlist_ ${boostish_})
      endforeach()
      foreach(boostish ${boostishlist_})
        list_filter(boostishlist_ EXCLUDE REGEX "${boostish}.+")
      endforeach()
      # Now we have an optimal boostishlist
      set(fileslist_ ${${fileslist}})
      foreach(boostish ${boostishlist_})
        list_filter(fileslist_ EXCLUDE REGEX "${boostish}")
      endforeach()
      set(${fileslist} ${fileslist_} PARENT_SCOPE)
    endif()
  endfunction()
  indented_message(STATUS "  Pruning globbed source file list of files not related to ${PROJECT_NAME} ...")
  prune_boostish_libraries(${PROJECT_NAME}_HEADERS_FILTER ${PROJECT_NAME}_HEADERS)
  prune_boostish_libraries(${PROJECT_NAME}_HEADERS_FILTER ${PROJECT_NAME}_INTERFACE_SOURCES)
  prune_boostish_libraries(${PROJECT_NAME}_SOURCES_FILTER ${PROJECT_NAME}_SOURCES)
  prune_boostish_libraries(${PROJECT_NAME}_TESTS_FILTER ${PROJECT_NAME}_TESTS)
  # MSVC has a cool feature where .natvis files tell the debugger how to display a type
  # We append this to the main interface header because we want all .natvis in all the
  # dependencies brought into anything we link
  if(MSVC)
    list(APPEND ${PROJECT_NAME}_INTERFACE ${${PROJECT_NAME}_INTERFACE_SOURCES})
  endif()

  #indented_message(STATUS "  ${PROJECT_NAME}_INTERFACE = ${${PROJECT_NAME}_INTERFACE}")
  #indented_message(STATUS "  ${PROJECT_NAME}_HEADERS = ${${PROJECT_NAME}_HEADERS}")
  #indented_message(STATUS "  ${PROJECT_NAME}_SOURCES = ${${PROJECT_NAME}_SOURCES}")
  #indented_message(STATUS "  ${PROJECT_NAME}_TESTS = ${${PROJECT_NAME}_TESTS}")
  list(LENGTH ${PROJECT_NAME}_HEADERS ${PROJECT_NAME}_HEADERS_COUNT)
  list(LENGTH ${PROJECT_NAME}_SOURCES ${PROJECT_NAME}_SOURCES_COUNT)
  list(LENGTH ${PROJECT_NAME}_TESTS ${PROJECT_NAME}_TESTS_COUNT)
  indented_message(STATUS "Project ${PROJECT_NAME} has ${${PROJECT_NAME}_HEADERS_COUNT} headers, "
                 "${${PROJECT_NAME}_SOURCES_COUNT} library sources and ${${PROJECT_NAME}_TESTS_COUNT} test sources.")

  # Take a hash of the current directory hierarchy so our shell slug in the output
  # build system can complain if new files were added without regening cmake
  if(WIN32)
    function(md5_source_tree path outvar)
      execute_process(COMMAND CMD /c dir /b /a-d /s
          OUTPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}\\boostlite_cmake_tempfile.txt"
          WORKING_DIRECTORY "${path}")
      file(MD5 "${CMAKE_CURRENT_BINARY_DIR}/boostlite_cmake_tempfile.txt" MD5)
      set(${outvar} ${MD5} PARENT_SCOPE)
    endfunction()
  else()
    function(md5_source_tree path outvar)
      execute_process(COMMAND find . -type f -printf "%t\t%s\t%p\n"
          OUTPUT_FILE "${CMAKE_CURRENT_BINARY_DIR}/boostlite_cmake_tempfile.txt"
          WORKING_DIRECTORY "${path}")
      file(MD5 "${CMAKE_CURRENT_BINARY_DIR}/boostlite_cmake_tempfile.txt" MD5)
      set(${outvar} ${MD5} PARENT_SCOPE)
    endfunction()
  endif()
  md5_source_tree("${${PROJECT_NAME}_PATH}/include" ${PROJECT_NAME}_HEADERS_MD5)
#  md5_source_tree("${${PROJECT_NAME}_PATH}/src" ${PROJECT_NAME}_SOURCES_MD5)
#  md5_source_tree("${${PROJECT_NAME}_PATH}/test" ${PROJECT_NAME}_TESTS_MD5)

  if(DEFINED ${PROJECT_NAME}_INTERFACE)
    set(${PROJECT_NAME}_INTERFACE ${${PROJECT_NAME}_INTERFACE}
      CACHE FILEPATH "The path to the precompilable master header file for the ${PROJECT_NAME} project")
  endif()
  if(DEFINED ${PROJECT_NAME}_INTERFACE_SOURCE)
    set(${PROJECT_NAME}_INTERFACE_SOURCE ${${PROJECT_NAME}_INTERFACE_SOURCE}
      CACHE FILEPATH "The path to the master C++ Module source file for the ${PROJECT_NAME} project")
  endif()
  set(${PROJECT_NAME}_HEADERS ${${PROJECT_NAME}_HEADERS}
    CACHE PATH "The path to the header files for the ${PROJECT_NAME} project")
  set(${PROJECT_NAME}_SOURCES ${${PROJECT_NAME}_SOURCES}
    CACHE PATH "The path to the source files for the ${PROJECT_NAME} project")
  set(${PROJECT_NAME}_TESTS ${${PROJECT_NAME}_TESTS}
    CACHE PATH "The path to the test files for the ${PROJECT_NAME} project")
  set(${PROJECT_NAME}_HEADERS_MD5 ${${PROJECT_NAME}_HEADERS_MD5}
    CACHE STRING "The hash of the header files directory tree for the ${PROJECT_NAME} project")
endif()
