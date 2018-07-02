# CTest script for a CI to submit to CDash a run of configuration,
# building and testing
cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
list(FIND CMAKE_MODULE_PATH "quickcpplib" quickcpplib_idx)
if(${quickcpplib_idx} EQUAL -1)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmakelib")
  set(CTEST_QUICKCPPLIB_SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts")
endif()
include(QuickCppLibUtils)


CONFIGURE_CTEST_SCRIPT_FOR_CDASH("outcome" "cmake_ci")
ctest_empty_binary_directory(${CTEST_BINARY_DIRECTORY})
include(FindGit)
set(CTEST_GIT_COMMAND "${GIT_EXECUTABLE}")

ctest_start("Experimental")
ctest_update()
ctest_configure()
ctest_build()
ctest_test(RETURN_VALUE retval)
merge_junit_results_into_ctest_xml()
#ctest_upload(FILES )
ctest_submit()
if(NOT retval EQUAL 0)
  message(FATAL_ERROR "FATAL: Running tests exited with ${retval}")
endif()
