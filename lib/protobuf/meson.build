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
	'user'
]

generated_protobufs = []
foreach protobuf_definition : protobuf_definitions
	generated_protobufs += custom_target(
			protobuf_definition,
			command: [
				protoc_c,
				'--proto_path=' + meson.current_source_dir(),
				'--c_out=@OUTDIR@',
				join_paths(meson.current_source_dir(), protobuf_definition + '.proto')
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

protobufs = static_library(
		'protobufs',
		generated_protobufs,
		c_args: protobuf_flags,
		dependencies: protobuf_c,
		override_options: ['werror=false', 'b_lto=false'],
		#include_directories: [protobuf_c_include]
		)

protobuf_include = include_directories('.')
