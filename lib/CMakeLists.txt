cmake_minimum_required (VERSION 2.6)

add_library(molch
	diffie-hellman
	key-derivation
	packet header
	header-and-message-keystore
	ratchet user-store
	spiced-random
	molch
	conversation
	conversation-store
	prekey-store
	master-keys
)
target_link_libraries(molch ${libs} molch-buffer mcjson)
