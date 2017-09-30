project('molch', ['cpp', 'c'],
	default_options: [
		'cpp_std=c++14',
		'c_std=c99',
		'werror=true',
		'b_pch=true'
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
	'-Wstrict-overflow=2',
	'-Wcast-qual',
	'-Wundef',
	'-Wswitch-default',
	'-Wconversion',
	'-fstack-protector-strong',
	'-Wcomma',
	'-Wdouble-promotion',
	'-Wparentheses',
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
	'-Wunsafe-loop-optimizations',
	'-Wredundant-decls',
	'-Wlogical-op',
	'-Wno-type-limits'
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
	'-Wsuggest-final-types',
	'-Wsuggest-final-methods',
	'-Wsuggest-override',
	'-Wc++1z-compat',
	'-Wconditionally-supported',
	'-Wzero-as-null-pointer-constant',
]

if ['debugoptimized', 'release'].contains(get_option('buildtype'))
	common_flags += [
		'-O3',
		'-U_FORTIFY_SOURCE',
		'-D_FORTIFY_SOURCE=2'
	]
endif

foreach common_flag : common_flags
	if c_compiler.has_argument(common_flag)
		add_project_arguments(common_flag, language: 'c')
	endif
	if cpp_compiler.has_argument(common_flag)
		add_project_arguments(common_flag, language: 'cpp')
	endif
endforeach

foreach cpp_flag : cpp_flags
	if cpp_compiler.has_argument(cpp_flag)
		add_project_arguments(cpp_flag, language: 'cpp')
	endif
endforeach

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
			timeout_multiplier: 10)
endif

subdir('lib')
subdir('test')
subdir('bindings')
