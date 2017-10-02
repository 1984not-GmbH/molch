project('libsodium', 'c', version: '1.0.14')

compiler = meson.get_compiler('c')

includes = include_directories('.')

libsodium = declare_dependency(
	dependencies: compiler.find_library(
		'sodium',
		dirs: join_paths(meson.current_source_dir(), host_machine.cpu())),
	include_directories: includes)
