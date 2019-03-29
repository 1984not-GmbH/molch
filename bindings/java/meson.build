if get_option('enable_java_bindings') and not ['address', 'undefined', 'address,undefined'].contains(get_option('b_sanitize'))
	jni_include_paths = get_option('jni_include_paths')
	if jni_include_paths.length() == 0
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

	cpp_jni_flag_candidates = [
		'-Wno-old-style-cast',
	]
	cpp_jni_flags = cpp_compiler.get_supported_arguments(cpp_jni_flag_candidates)

	molchJNI_cpp_sources = files([
		'MolchJNI.cpp',
		'1984notlib.cpp',
	])

	molchJNI_cpp = library(
		'molchJNI++',
		molchJNI_cpp_sources,
		link_with: molch,
		include_directories: [
			java_include_paths,
			molch_include,
		],
		dependencies: [libsodium],
		cpp_args: cpp_jni_flags)

	c_jni_flag_candidates = [
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
	c_jni_flags = c_compiler.get_supported_arguments(c_jni_flag_candidates)

	molchJNI_sources = files([
		'1984notlib.c',
		'MolchJNI.c',
	])

	molchJNI = library(
		'molchJNI',
		molchJNI_sources,
		link_with: molch,
		include_directories: [
			java_include_paths,
			molch_include,
		],
		dependencies: [libsodium],
		c_args: c_jni_flags)

	molch_jni_sources = files([
		'molch-jni.cpp',
	])
	molch_jni = library(
		'molch-jni',
		molch_jni_sources,
		link_with: molch,
		dependencies: [
			libsodium,
		],
		include_directories: [
			java_include_paths,
			molch_include,
		])
endif
