# - Find Protoc-C
# Find the protobuf-c compiler/code generator.
# Once done this will define
#
#  PROTOC_C_EXECUTABLE - Executable of the protobuf-c compiler.
#  PROTOC_C_FOUND      - True if the protobuf-c compiler was found.
#

find_program(PROTOC_C_EXECUTABLE NAMES protoc-c HINTS ${PROTOBUFC_ROOT_DIR}/protoc-c)

# handle the QUIETLY and REQUIRED arguments and set PROTOC_Cto TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PROTOC_C REQUIRED_VARS PROTOC_C_EXECUTABLE)

mark_as_advanced(PROTOC_C_EXECUTABLE)
