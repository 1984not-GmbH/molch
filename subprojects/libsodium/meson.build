project('libsodium', 'c', version: '1.0.13')

compiler = meson.get_compiler('c')

includes = include_directories('.')

libsodium = declare_dependency(
	dependencies: compiler.find_library('sodium', dirs: meson.current_source_dir()),
	include_directories: includes)
