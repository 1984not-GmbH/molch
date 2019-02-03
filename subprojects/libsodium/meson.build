project('libsodium', 'c', version: '1.0.14')

compiler = meson.get_compiler('c')

base_path = join_paths(meson.current_source_dir, host_machine.cpu())
includes = include_directories(join_paths(base_path, 'include')

libsodium = declare_dependency(
	dependencies: compiler.find_library(
		'sodium',
		dirs: join_paths(base_path, 'lib'),
	include_directories: includes)
