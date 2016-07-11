# - Find Protobuf-C
# Find the native Protobuf-C includes and library.
# Once done this will define
#
#  PROTOBUFC_INCLUDE_DIR  - where to find protobuf-c header files, etc.
#  PROTOBUFC_LIBRARY      - List of libraries when using protobuf-c.
#  PROTOBUFC_FOUND        - True if protobuf-c was found.
#

find_library(PROTOBUFC_LIBRARY NAMES protobuf-c libprotobuf-c HINTS ${PROTOBUFC_ROOT_DIR}/protobuf-c/.libs)
find_path(PROTOBUFC_INCLUDE_DIR NAMES protobuf-c/protobuf-c.h ${PROTOBUFC_ROOT_DIR})

# handle the QUIETLY and REQUIRED arguments and set PROTOBUFC_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PROTOBUFC REQUIRED_VARS PROTOBUFC_LIBRARY PROTOBUFC_INCLUDE_DIR)

mark_as_advanced(PROTOBUFC_LIBRARY PROTOBUFC_INCLUDE_DIR)
