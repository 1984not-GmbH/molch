tests = [
		'diffie-hellman-test',
		'triple-diffie-hellman-test',
		'key-derivation-test',
		'chain-key-derivation-test',
		'message-key-derivation-test',
		'root-next-header-and-chain-key-derivation-test',
		'initial-root-chain-and-header-key-derivation-test',
		'packet-get-metadata-test',
		'packet-decrypt-header-test',
		'packet-decrypt-message-test',
		'packet-decrypt-test',
		'header-test',
		'header-and-message-keystore-test',
		'ratchet-test',
		'ratchet-test-simple',
		'user-store-test',
		'spiced-random-test',
		'molch-test',
		'conversation-test',
		'conversation-packet-test',
		'conversation-store-test',
		'prekey-store-test',
		'master-keys-test',
		'endianness-test',
		'return-status-test',
		'molch-init-test',
		'buffer-test',
		'molch-exception-test',
		'protobuf-pool-test',
		'optional-test'
]

test_library = library(
		'test-library',
		[
			'utils.cpp',
			'common.cpp',
			'packet-test-lib.cpp'
		],
		include_directories: protobuf_include,
		link_with: [molch, protobufs],
		dependencies: [
			libsodium,
			protobuf_c
		])

foreach test : tests
	test_exe = executable(
			test,
			test + '.cpp',
			link_with: [test_library, molch, protobufs],
			include_directories: protobuf_include,
			dependencies: [
				libsodium,
				protobuf_c
			])
	test(test, test_exe, workdir: meson.current_source_dir())
endforeach
