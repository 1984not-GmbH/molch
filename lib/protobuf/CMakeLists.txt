cmake_minimum_required (VERSION 2.6)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(proto-files
	header
	packet
	packet_header
	backup
	conversation
	encrypted_backup
	key
	key_bundle
	prekey
	user)

foreach(proto-file ${proto-files})
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${proto-file}.pb-c.h ${CMAKE_CURRENT_BINARY_DIR}/${proto-file}.pb-c.c
		COMMAND "${PROTOC_C_EXECUTABLE}"
		ARGS
			--c_out="${CMAKE_CURRENT_BINARY_DIR}"
			--proto_path="${CMAKE_CURRENT_SOURCE_DIR}"
			"${CMAKE_CURRENT_SOURCE_DIR}/${proto-file}.proto"
		COMMENT "Compiling ${proto-file}.proto.")

	list(APPEND proto-headers "${CMAKE_CURRENT_BINARY_DIR}/${proto-file}.pb-c.h")
	list(APPEND proto-sources "${CMAKE_CURRENT_BINARY_DIR}/${proto-file}.pb-c.c")
endforeach()

set_source_files_properties(${proto-sources} ${proto-headers} PROPERTIES GENERATED TRUE)

add_library(protocol-buffers ${proto-sources})
target_link_libraries(protocol-buffers ${PROTOBUFC_LIBRARY})
