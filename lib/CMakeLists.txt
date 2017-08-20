cmake_minimum_required (VERSION 2.6)

subdirs(protobuf)
include_directories("${CMAKE_CURRENT_BINARY_DIR}/protobuf")

add_library(molch
	diffie-hellman
	key-derivation
	packet
	header
	header-and-message-keystore
	ratchet user-store
	spiced-random
	molch
	conversation
	conversation-store
	prekey-store
	master-keys
	return-status
	zeroed_malloc
	buffer
	molch-exception
	protobuf.cpp #file extension required to distinguish from the protobuf directory
	protobuf-pool
)
target_link_libraries(molch ${libs} protocol-buffers)
