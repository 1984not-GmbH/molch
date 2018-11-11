project('molch', ['cpp', 'c'],
	default_options: [
		'cpp_std=c++17',
		'c_std=c99',
		'werror=true',
		'b_pch=true',
		'b_pie=true',
	  ],
	license: ['ISC'])

c_compiler = meson.get_compiler('c')
cpp_compiler = meson.get_compiler('cpp')

common_flags = [
	'-pedantic',
	'-Wall',
	'-Wextra',
	'-Wwrite-strings',
	'-Winit-self',
	'-Wformat=2',
	'-Wcast-qual',
	'-Wswitch-default',
	'-Wconversion',
	'-fstack-protector-all',
	'-Wcomma',
	'-Wdouble-promotion',
	'-Wno-parentheses',
	'-fPIC',
	'-Wunused-macros',
	'-Wmissing-variable-declarations',
	'-Wchkp',
	'-Wnull-dereference',
	'-Wimplicit-fallthrough',
	'-Wunused-parameter',
	'-Wstrict-aliasing=1',
	'-Walloc-zero',
	'-Walloca',
	'-Wduplicated-branches',
	'-Wduplicated-cond',
	'-Wfloat-equal',
	'-Wtrampolines',
	'-Wredundant-decls',
	'-Wlogical-op',
	'-Wno-type-limits',
	'-fno-sanitize-recover=all',
	'-Wunreachable-code',
	'-Wdocumentation',
	'-Wmissing-noreturn',
	'-Wswitch-enum',
	'-fvisibility=hidden',
	'-Wno-unknown-warning-option',
	'-Wno-tautological-constant-compare',
	'-Wno-pragmas',
]

c_flags = [
	'-Wmissing-prototypes',
]

cpp_flags = [
	'-Wnoexcept',
	'-Wstrict-null-sentinel',
	'-Wold-style-cast',
	'-Woverloaded-virtual',
	'-Wsign-promo',
	'-Wmultiple-inheritance',
	'-Wvirtual-inheritance',
	'-Wuninitialized',
	'-Wsuggest-override',
	'-Wconditionally-supported',
	'-Wzero-as-null-pointer-constant',
	'-Wrange-loop-analysis',
	'-Wunused-exception-parameter',
]

if ['debugoptimized', 'release'].contains(get_option('buildtype'))
	common_flags += [
		'-O3',
		'-U_FORTIFY_SOURCE',
		'-D_FORTIFY_SOURCE=2'
	]
endif

supported_c_flags = c_compiler.get_supported_arguments(common_flags + c_flags)
supported_cpp_flags = cpp_compiler.get_supported_arguments(common_flags + cpp_flags)

add_project_arguments(supported_c_flags, language: 'c')
add_project_arguments(supported_cpp_flags, language: 'cpp')

linker_flags = [
	'-znoexecstack',
	'-znow',
	'-zrelro',
	'-ztext',
]

supported_c_linker_flags = c_compiler.get_supported_link_arguments(linker_flags)
supported_cpp_linker_flags = cpp_compiler.get_supported_link_arguments(linker_flags)
add_project_link_arguments(supported_c_linker_flags, language: 'c')
add_project_link_arguments(supported_cpp_linker_flags, language: 'cpp')


#valgrind
valgrind = find_program('valgrind', required: false)
if valgrind.found()
	add_test_setup(
			'valgrind',
			exe_wrapper: [
				valgrind,
				'--suppressions=' + join_paths(meson.current_source_dir(), 'valgrind.supp'),
				'--trace-children=yes',
				'--leak-check=full',
				'--error-exitcode=10'
			],
			timeout_multiplier: 100)
endif

subdir('include')
subdir('lib')
subdir('test')
subdir('bindings')
