libsodium = dependency('libsodium', version: '>=1.0.14', required: false)
if not libsodium.found()
	libsodium = subproject('libsodium').get_variable('libsodium')
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
		'conversation.cpp',
		'conversation-store.cpp',
		'prekey-store.cpp',
		'master-keys.cpp',
		'return-status.cpp',
		'error.cpp',
		'protobuf.cpp',
		'sodium-wrappers.cpp',
		'time.cpp',
		'protobuf-arena.cpp'
)

gsl_include = include_directories('../gsl/include')
outcome_include = include_directories('../outcome/include')
molch_internals = static_library(
	'molch_internals',
	lib_sources,
	dependencies: [
		libsodium,
		protobuf_lite,
		protobuf_c,
	],
	link_with: c_protobufs,
	include_directories: [
		c_protobufs_include,
		gsl_include,
		outcome_include,
	],
	implicit_include_directories: false,
)
molch = library(
		'molch',
		files('molch.cpp'),
		dependencies: [
			libsodium,
			protobuf_c,
			protobuf_lite,
		],
		link_with: molch_internals,
		include_directories: [
			c_protobufs_include,
			gsl_include,
			outcome_include,
		],
		implicit_include_directories: false,
		install: true)
