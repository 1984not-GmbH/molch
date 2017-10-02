libsodium = dependency('libsodium', version: '>=1.0.13', required: false)
sodium_include = include_directories()
if not libsodium.found()
	libsodium_project = subproject('libsodium')
	libsodium = libsodium_project.get_variable('libsodium')
	sodium_include = libsodium_project.get_variable('includes')
endif

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

gsl_include = include_directories('../gsl/include')
molch = library(
		'molch',
		lib_sources,
		dependencies: libsodium,
		link_with: protobufs,
		include_directories: [protobuf_include, gsl_include, protobuf_c_include, sodium_include],
		install: true)