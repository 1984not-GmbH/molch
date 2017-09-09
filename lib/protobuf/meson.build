protobuf_c = dependency('libprotobuf-c', required: false)
protobuf_c_includes = include_directories()
if not protobuf_c.found()
	protobuf_c = subproject('protobuf-c').get_variable('protobuf_c')
	protobuf_c_includes = include_directories('../../subprojects/protobuf-c')
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

protobufs = library(
		'protobufs',
		generated_protobufs,
		dependencies: protobuf_c,
		override_options: 'werror=false')

protobuf_include = include_directories('.')
