project('protobuf-c', ['c'], version: '1.3.0')

compiler = meson.get_compiler('c')

includes = include_directories('.')

protobuf_c_lib = library('protobuf-c', 'protobuf-c/protobuf-c.c', install: true)
protobuf_c = declare_dependency(
		link_with: protobuf_c_lib,
		include_directories: includes)
