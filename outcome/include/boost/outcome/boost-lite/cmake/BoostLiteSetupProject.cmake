# Set up this cmake environment for this project

# Bring in CTest support
include(CTest)
# Bring in threads, this is after all the 21st century
find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT})
# Find a python installation, if we have one we can do preprocessing
include(FindPythonInterp)

# On MSVC very annoyingly cmake puts /EHsc and /MD(d) into the global flags which means you
# get a warning when you try to disable exceptions or use the static CRT. I hate to use this
# globally imposed solution, but we are going to hack the global flags to use properties to
# determine whether they are on or off
#
# Create custom properties called CXX_EXCEPTIONS, CXX_RTTI and CXX_STATIC_RUNTIME
# These get placed at global, directory and target scopes
foreach(scope GLOBAL DIRECTORY TARGET)
  define_property(${scope} PROPERTY "CXX_EXCEPTIONS" INHERITED
    BRIEF_DOCS "Enable C++ exceptions, defaults to ON at global scope"
    FULL_DOCS "Not choosing ON nor OFF with exact capitalisation will lead to misoperation!"
  )
  define_property(${scope} PROPERTY "CXX_RTTI" INHERITED
    BRIEF_DOCS "Enable C++ runtime type information, defaults to ON at global scope"
    FULL_DOCS "Not choosing ON nor OFF with exact capitalisation will lead to misoperation!"
  )
  define_property(${scope} PROPERTY "CXX_STATIC_RUNTIME" INHERITED
    BRIEF_DOCS "Enable linking against the static C++ runtime, defaults to OFF at global scope"
    FULL_DOCS "Not choosing ON nor OFF with exact capitalisation will lead to misoperation!"
  )
endforeach()
# Set the default for these properties at global scope. If they are not set per target or
# whatever, the next highest scope will be looked up
set_property(GLOBAL PROPERTY CXX_EXCEPTIONS ON)
set_property(GLOBAL PROPERTY CXX_RTTI ON)
set_property(GLOBAL PROPERTY CXX_STATIC_RUNTIME OFF)
if(MSVC AND NOT CLANG)
  # Purge unconditional use of /MDd, /MD and /EHsc.
  foreach(flag
          CMAKE_C_FLAGS                CMAKE_CXX_FLAGS
          CMAKE_C_FLAGS_DEBUG          CMAKE_CXX_FLAGS_DEBUG
          CMAKE_C_FLAGS_RELEASE        CMAKE_CXX_FLAGS_RELEASE
          CMAKE_C_FLAGS_MINSIZEREL     CMAKE_CXX_FLAGS_MINSIZEREL
          CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO
          )
    string(REPLACE "/MDd"  "" ${flag} "${${flag}}")
    string(REPLACE "/MD"   "" ${flag} "${${flag}}")
    string(REPLACE "/EHsc" "" ${flag} "${${flag}}")
    string(REPLACE "/GR" "" ${flag} "${${flag}}")
  endforeach()
  # Restore those same, but now selected by the properties
  add_compile_options(
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_EXCEPTIONS>,ON>:/EHsc>
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_RTTI>,OFF>:/GR->
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_STATIC_RUNTIME>,OFF>:$<$<CONFIG:Debug>:/MDd>$<$<NOT:$<CONFIG:Debug>>:/MD>>
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_STATIC_RUNTIME>,ON>:$<$<CONFIG:Debug>:/MTd>$<$<NOT:$<CONFIG:Debug>>:/MT>>
  )
else()
  add_compile_options(
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_EXCEPTIONS>,ON>:-fexceptions>
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_RTTI>,ON>:-frtti>
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_EXCEPTIONS>,OFF>:-fno-exceptions>
    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_RTTI>,OFF>:-fno-rtti>
#    $<$<STREQUAL:$<TARGET_PROPERTY:CXX_STATIC_RUNTIME>,ON>:-static>
  )
endif()

# Scan this directory for library source code
include(BoostLiteDeduceLibrarySources)

# Configure an if(CLANG) and if(GCC) like if(MSVC)
if(NOT DEFINED CLANG)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CLANG 1)
  endif()
endif()
if(NOT DEFINED GCC)
  if(CMAKE_COMPILER_IS_GNUCXX)
    set(GCC 1)
  elseif(NOT MSVC AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(GCC 1)
  endif()
endif()
#message(STATUS "CMAKE_CXX_COMPILER_ID=${CMAKE_CXX_COMPILER_ID} MSVC=${MSVC} CLANG=${CLANG} GCC=${GCC}")

set(SPECIAL_BUILDS)  ## Used to add optional build targets for every build target

# Configure the static analyser build
if(MSVC AND NOT CLANG)
  list(APPEND SPECIAL_BUILDS sa)
  set(sa_COMPILE_FLAGS /analyze /analyze:stacksize 262144)  ## Chosen because OS X enforces this limit on stack usage
  #set(sa_LINK_FLAGS)
endif()
option(ENABLE_CLANG_STATIC_ANALYZER "Enable the clang static analyser as a special build. Be aware almost certainly the object files generated will not link, but it can be useful to enable this in a pinch rather than setting up scan-build" OFF)
if(CLANG AND ENABLE_CLANG_STATIC_ANALYZER)
  list(APPEND SPECIAL_BUILDS sa)
  set(sa_COMPILE_FLAGS --analyze)
  #set(sa_LINK_FLAGS)
endif()

if(GCC OR CLANG)
  # Does this compiler have the santisers?
  include(CheckCXXSourceCompiles)
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_UBSAN)
  if(COMPILER_HAS_UBSAN)
    set(ubsan_COMPILE_FLAGS -fsanitize=undefined -fno-omit-frame-pointer -g)
    set(ubsan_LINK_FLAGS -fsanitize=undefined)
    list(APPEND SPECIAL_BUILDS ubsan)
  endif()
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_ASAN)
  if(COMPILER_HAS_ASAN)
    if(COMPILER_HAS_UBSAN)
      set(asan_COMPILE_FLAGS -fsanitize=address ${ubsan_COMPILE_FLAGS})
      set(asan_LINK_FLAGS -fsanitize=address ${ubsan_LINK_FLAGS})
    else()
      set(asan_COMPILE_FLAGS -fsanitize=address -fno-omit-frame-pointer -g)
      set(asan_LINK_FLAGS -fsanitize=address)
    endif()
    list(APPEND SPECIAL_BUILDS asan)
  endif()
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=memory")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_MSAN)
  if(COMPILER_HAS_MSAN)
    set(msan_COMPILE_FLAGS -fsanitize=memory ${ubsan_COMPILE_FLAGS})
    set(msan_LINK_FLAGS -fsanitize=memory ${ubsan_LINK_FLAGS})
    list(APPEND SPECIAL_BUILDS msan)
  endif()
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=thread")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_TSAN)
  if(COMPILER_HAS_TSAN)
    set(tsan_COMPILE_FLAGS -fsanitize=thread ${ubsan_COMPILE_FLAGS})
    set(tsan_LINK_FLAGS -fsanitize=thread ${ubsan_LINK_FLAGS})
    list(APPEND SPECIAL_BUILDS tsan)
  endif()
  unset(CMAKE_REQUIRED_FLAGS)
  foreach(special ${SPECIAL_BUILDS})
    set(${PROJECT_NAME}_${special}_TARGETS)
  endforeach()

  # This fellow probably ought to be compiled into every executable
  set(CMAKE_REQUIRED_FLAGS "-fsanitize=safestack")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_SAFESTACK)
  if(COMPILER_HAS_SAFESTACK)
    set(SAFESTACK_COMPILE_FLAGS -fsanitize=safestack)
    set(SAFESTACKLINK_FLAGS -fsanitize=safestack)
  endif()
  # This fellow probably should just always be turned on period
  set(CMAKE_REQUIRED_FLAGS "-fstack-protector-strong")
  check_cxx_source_compiles("int main() { return 0; }" COMPILER_HAS_STACK_PROTECTOR)
  if(COMPILER_HAS_STACK_PROTECTOR)
    set(STACK_PROTECTOR_COMPILE_FLAGS -fstack-protector-strong)
  endif()
  add_compile_options(${STACK_PROTECTOR_COMPILE_FLAGS})  ## everything gets this flag
endif()

# Create custom category targets to build all of some kind of thing
if(NOT TARGET _hl)
  add_custom_target(_hl COMMENT "Building all header-only library based code ...")
endif()
if(NOT TARGET _sl)
  add_custom_target(_sl COMMENT "Building all static library based code ...")
endif()
if(NOT TARGET _dl)
  add_custom_target(_dl COMMENT "Building all dynamic library based code ...")
endif()
if(NOT TARGET _docs)
  add_custom_target(_docs COMMENT "Building all documentation ...")
endif()
foreach(special ${SPECIAL_BUILDS})
  if(NOT TARGET _${special})
    add_custom_target(_${special} COMMENT "Building special build ${special} ...")
  endif()
endforeach()
