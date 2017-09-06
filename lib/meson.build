libsodium = dependency('libsodium', version: '>=1.0.13')

subdir('protobuf')

lib_sources = files(
		'diffie-hellman.cpp',
		'key-derivation.cpp',
		'packet.cpp',
		'header.cpp',
		'header-and-message-keystore.cpp',
		'ratchet.cpp',
		'user-store.cpp',
		'spiced-random.cpp',
		'molch.cpp',
		'conversation.cpp',
		'conversation-store.cpp',
		'prekey-store.cpp',
		'master-keys.cpp',
		'return-status.cpp',
		'molch-exception.cpp',
		'protobuf.cpp',
		'protobuf-pool.cpp',
		'optional.cpp',
		'sodium-wrappers.cpp'
)

molch = library(
		'molch',
		lib_sources,
		dependencies: libsodium,
		link_with: protobufs,
		include_directories: protobuf_include,
		install: true)
