project('libsodium', 'c', version: '1.0.13')

compiler = meson.get_compiler('c')

includes = include_directories('.')

libsodium = declare_dependency(
	dependencies: compiler.find_library('sodium', dirs: meson.current_source_dir()),
	include_directories: includes)

#check the library version
correct_version = compiler.compiles(
	'#include <sodium.h>\n' +
	'#if (SODIUM_LIBRARY_VERSION_MAJOR != 9) || (SODIUM_LIBRARY_VERSION_MINOR != 5)\n' +
	'#error "Incorrect libsodium version"\n' +
	'#endif',
	include_directories: includes)
if not correct_version
	error('Libsodium has an incorrect version.')
endif
