# CTest script for a CI to submit to CDash a documentation generation run
cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
list(FIND CMAKE_MODULE_PATH "quickcpplib/cmake" quickcpplib_idx)
if(${quickcpplib_idx} EQUAL -1)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmakelib")
endif()
include(QuickCppLibUtils)


CONFIGURE_CTEST_SCRIPT_FOR_CDASH("quickcpplib" "cmake_ci")
ctest_empty_binary_directory(${CTEST_BINARY_DIRECTORY})
include(FindGit)
set(CTEST_GIT_COMMAND "${GIT_EXECUTABLE}")
#checked_execute_process("git reset"
#  COMMAND "${GIT_EXECUTABLE}" checkout gh-pages
#  COMMAND "${GIT_EXECUTABLE}" reset --hard ae7119571a3c81cb9a683a21f2759df1d742e998
#  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/doc/html"
#)

ctest_start("Documentation")
ctest_update()
checked_execute_process("git reset"
  COMMAND "${GIT_EXECUTABLE}" checkout gh-pages
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/doc/html"
)
ctest_configure()
ctest_build(TARGET quickcpplib_docs)
#checked_execute_process("git commit"
#  COMMAND "${GIT_EXECUTABLE}" commit -a -m "upd"
#  COMMAND "${GIT_EXECUTABLE}" push -f origin gh-pages
#  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/doc/html"
#)
ctest_submit()
