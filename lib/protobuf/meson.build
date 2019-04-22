protobuf_lite = dependency('protobuf-lite', required: false)
if not protobuf_lite.found()
	protobuf_lite = subproject('protobuf').get_variable('protobuf_lite_dep')
endif
protoc = find_program('protoc')

protobuf_c = dependency('libprotobuf-c', required: false)
if not protobuf_c.found()
	protobuf_c = subproject('protobuf-c').get_variable('protobuf_c')
endif
protoc_c = find_program('protoc-c')

protobuf_definitions = [
	'header',
	'packet',
	'packet_header',
	'backup',
	'conversation',
	'encrypted_backup',
	'key',
	'key_bundle',
	'prekey',
	'user',
	'public_prekey',
	'prekey_list',
	'signed_prekey_list',
]

generated_c_protobufs = []
foreach protobuf_definition : protobuf_definitions
	generated_c_protobufs += custom_target(
			'c_' + protobuf_definition,
			command: [
				protoc_c,
				'--proto_path=@CURRENT_SOURCE_DIR@',
				'--c_out=@OUTDIR@',
				'@INPUT@'
			],
			input: protobuf_definition + '.proto',
			output: ['@BASENAME@.pb-c.h', '@BASENAME@.pb-c.c'])
endforeach

proposed_protobuf_flags = [
	'-Wno-strict-aliasing'
]
protobuf_flags = []
foreach flag : proposed_protobuf_flags
	if c_compiler.has_argument(flag)
		protobuf_flags += flag
	endif
endforeach

c_protobufs = static_library(
		'c_protobufs',
		generated_c_protobufs,
		c_args: protobuf_flags,
		dependencies: protobuf_c,
		override_options: ['werror=false', 'b_lto=false'])

c_protobufs_include = include_directories('.')
