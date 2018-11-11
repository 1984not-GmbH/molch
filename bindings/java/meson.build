jni_sources = files([
	'MolchJNI.c',
	'1984notlib.c',
])

java_include_candidates = [
	'/usr/lib/jvm/java-8-jdk/include',
	'/usr/lib/jvm/java-8-openjdk/include',
	'/usr/lib/jvm/java-9-jdk/include',
	'/usr/lib/jvm/java-9-openjdk/include',
	'/usr/lib/jvm/java-10-jdk/include',
	'/usr/lib/jvm/java-10-openjdk/include',
	'/usr/lib/jvm/java-11-jdk/include',
	'/usr/lib/jvm/java-11-openjdk/include',
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

jni = library(
	'molchJNI',
	jni_sources,
	link_with: molch,
	include_directories: [
		java_include,
		molch_include,
	])
