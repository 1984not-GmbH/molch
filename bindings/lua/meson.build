if get_option('lua_bindings') and not ['address', 'undefined', 'address,undefined'].contains(get_option('b_sanitize')) and not (build_machine.system() == 'darwin')
	swig = find_program('swig', required: true)

	molch_interface_source = custom_target(
			'molch_interface_source',
			command: [
				swig,
				'-lua',
				'-I' + meson.source_root(),
				'-o',
				'@OUTPUT@',
				'@INPUT@'
			],
			input: 'molch.i',
			output: '@BASENAME@_wrap.c')

	liblua = dependency('lua', version: '>=5.2')

	proposed_swig_flags = [
		'-Wno-conversion',
		'-Wno-unused-macros',
		'-Wno-cast-qual',
		'-Wno-missing-prototypes',
		'-Wno-strict-aliasing',
		'-Wno-maybe-uninitialized',
		'-Wno-missing-variable-declarations',
		'-Wno-unreachable-code',
	]
	swig_flags = []
	foreach flag : proposed_swig_flags
		if c_compiler.has_argument(flag)
			swig_flags += flag
		endif
	endforeach

	root_includes = include_directories('../')
	molch_interface = library(
			'molch-interface',
			molch_interface_source,
			include_directories: [
				root_includes,
				molch_include,
			],
			link_with: molch,
			dependencies: [liblua, libsodium],
			name_prefix: '', #so that lua loads the correct library file
			override_options: 'werror=false',
			c_args: swig_flags)

	#install molch.lua
	configure_file(input: 'molch.lua', output: 'molch.lua', copy: true)

	# [name, should_fail]
	scenarios = [
		['normal-conversation', false],
		['reordering', false],
		['invalid_message', false],
		['double-import', false],
		['restart', false],
		['fail', true]
	]

	lua = find_program('lua5.3', 'lua53', 'lua5.2', 'lua52', 'lua')

	foreach scenario : scenarios
		test(
				'scenario: ' + scenario.get(0),
				lua,
				args: files(
					join_paths('scenarios', 'scenarios.lua'),
					join_paths('scenarios', scenario.get(0))),
				workdir: meson.current_build_dir(),
				should_fail: scenario.get(1))
	endforeach

endif

