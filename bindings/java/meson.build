jnipp_sources = files([
	'MolchJNI.cpp',
	'1984notlib.cpp',
])

java_include_candidates = [
	'/usr/lib/jvm/java-8-jdk/include',
	'/usr/lib/jvm/java-8-openjdk/include',
	'/usr/lib/jvm/java-8-openjdk-amd64/include',
	'/usr/lib/jvm/java-9-jdk/include',
	'/usr/lib/jvm/java-9-openjdk/include',
	'/usr/lib/jvm/java-9-openjdk-amd64/include',
	'/usr/lib/jvm/java-10-jdk/include',
	'/usr/lib/jvm/java-10-openjdk/include',
	'/usr/lib/jvm/java-10-openjdk-amd64/include',
	'/usr/lib/jvm/java-11-jdk/include',
	'/usr/lib/jvm/java-11-openjdk/include',
	'/usr/lib/jvm/java-11-openjdk-amd64/include',
	'/usr/lib/jvm/java-12-jdk/include',
	'/usr/lib/jvm/java-12-openjdk/include',
	'/usr/lib/jvm/java-12-openjdk-amd64/include',
]

winning_java_include = ''
foreach java_include_candidate : java_include_candidates
	if cpp_compiler.has_header(java_include_candidate + '/jni.h')
		winning_java_include = java_include_candidate
	endif
endforeach

if build_machine.system() == 'linux'
	java_include = include_directories([
		winning_java_include,
		winning_java_include + '/linux'
	])
else
	java_include = include_directories(winning_java_include)
endif

jnipp_flag_candidates = [
	'-Wno-old-style-cast',
	'-Wno-sign-compare',
]
jnipp_flags = cpp_compiler.get_supported_arguments(jnipp_flag_candidates)

jnipp = library(
	'molchJNI++',
	jnipp_sources,
	link_with: molch,
	include_directories: [
		java_include,
		molch_include,
	],
	dependencies: [libsodium],
	cpp_args: jnipp_flags)

jni_sources = files([
	'1984notlib.c',
	'MolchJNI.c'
])

jni_flag_candidates = [
	'-Wno-discarded-qualifiers',
	'-Wno-sign-compare',
	'-Wno-unused-variable',
	'-Wno-sign-conversion',
	'-Wno-conversion',
	'-Wno-pointer-sign',
	'-Wno-cast-qual',
	'-Wno-unused-parameter',
	'-Wno-unused-but-set-variable',
	'-Wno-incompatible-pointer-types-discards-qualifiers',
]

jni_flags = c_compiler.get_supported_arguments(jni_flag_candidates)

jni = library(
	'molchJNI',
	jni_sources,
	link_with: molch,
	include_directories: [
		java_include,
		molch_include,
	],
	dependencies: [libsodium],
	c_args: jni_flags)
