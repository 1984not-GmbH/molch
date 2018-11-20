if get_option('enable_java_bindings') and not ['address', 'undefined', 'address,undefined'].contains(get_option('b_sanitize'))
	jni_include_paths = get_option('jni_include_paths')
	if jni_include_paths.length() == 0
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
			java_include_paths = include_directories([
				winning_java_include,
				winning_java_include + '/linux'
			])
		else
			java_include_paths = include_directories(winning_java_include)
		endif
	endif


	molch_jni_sources = files([
		'molch-jni.cpp',
	])
	molch_jni = library(
		'molch-jni',
		molch_jni_sources,
		link_with: molch,
		include_directories: [
			java_include_paths,
			molch_include,
		])
endif
