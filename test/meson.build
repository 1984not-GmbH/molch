unit_tests = [
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
		'conversation-test',
		'conversation-packet-test',
		'conversation-store-test',
		'prekey-store-test',
		'master-keys-test',
		'endianness-test',
		'return-status-test',
		'buffer-test',
		'time-test',
		'copy-test',
]

integration_tests = [
	'molch-test',
	'molch-init-test',
]

test_library = static_library(
		'test-library',
		[
			'utils.cpp',
			'common.cpp',
			'packet-test-lib.cpp',
			'exception.cpp',
		],
		include_directories: [
			c_protobufs_include,
			gsl_include,
			outcome_include,
			molch_include,
		],
		link_with: molch_internals,
		dependencies: [
			libsodium,
			protobuf_lite,
			protobuf_c
		]
)

foreach test : unit_tests
	test_exe = executable(
		test,
		test + '.cpp',
		link_with: [
			test_library,
			c_protobufs,
			molch_internals
		],
		dependencies: [
			libsodium,
			protobuf_lite,
			protobuf_c,
		],
		include_directories: [
			c_protobufs_include,
			gsl_include,
			outcome_include,
			molch_include,
		]
	)
	test(test, test_exe, workdir: meson.current_source_dir())
endforeach

integration_test_library = static_library(
		'integration-test-library',
		[
			'integration-utils.cpp',
		],
		dependencies: [
			libsodium,
		],
		include_directories: [
			c_protobufs_include,
			molch_include,
		])

foreach test : integration_tests
	test_exe = executable(
		test,
		test + '.cpp',
		link_with: [
			molch,
			integration_test_library,
			c_protobufs,
		],
		dependencies: [libsodium, protobuf_c, protobuf_lite],
		include_directories: [
			c_protobufs_include,
			outcome_include,
			gsl_include,
			molch_include,
		]
	)
	test(test, test_exe, workdir: meson.current_source_dir())
endforeach

if ['undefined', 'address,undefined'].contains(get_option('b_sanitize'))
	ubsan_test = executable('ubsan-test', 'ubsan-test.cpp')
	test('ubsan-test', ubsan_test, should_fail: true)
endif

if ['address', 'address,undefined'].contains(get_option('b_sanitize'))
	asan_test = executable('asan-test', 'asan-test.cpp')
	test('asan-test', asan_test, should_fail: true)
endif
