project('libsodium', 'c', version: '1.0.18')

compiler = meson.get_compiler('c')

includes = include_directories(join_paths('libsodium-android-' + host_machine.cpu(), 'include'))

libsodium = declare_dependency(
	dependencies: compiler.find_library(
		'sodium',
		dirs: join_paths(meson.current_source_dir(), 'libsodium-android-' + host_machine.cpu(), 'lib')),
	include_directories: includes)
