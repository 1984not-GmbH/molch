#!/usr/bin/env bash

function make_clang_wrapper() {
	local compiler_path="$1"
	local wrapper_path="$2"

	local clang_wrapper="#!/usr/bin/env bash

# This is a wrapper around the compiler that undefines _FILE_OFFSET_BITS.
# This is necessary for compiling C++ code with Meson, since it stupidly sets _FILE_OFFSET_BITS=64 without any apparent way of turning it off
${compiler_path} \"\$@\" -U_FILE_OFFSET_BITS
"

	echo "$clang_wrapper" > "$wrapper_path"
	chmod +x "$wrapper_path"
}

function make_cross_file() {
	local architecture=$1
	local isa="$2"
	local cpu="$3"
	local abi="$4"
	local compiler_prefix="$5"
	local compiler_flags="$6"
	local linker_flags="$7"

	local tools_directory=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin
	local tool_prefix="${isa}-linux-${abi}"

	make_clang_wrapper "${tools_directory}/${compiler_prefix}-clang" "${PWD}/wrappers/${isa}-clang-wrapper.sh"
	make_clang_wrapper "${tools_directory}/${compiler_prefix}-clang++" "${PWD}/wrappers/${isa}-clang++-wrapper.sh"

	local crossfile="[binaries]
c = '${PWD}/wrappers/${isa}-clang-wrapper.sh'
cpp = '${PWD}/wrappers/${isa}-clang++-wrapper.sh'
strip = '${tools_directory}/${isa}-linux-${abi}-strip'
ar = '${tools_directory}/${isa}-linux-${abi}-ar'
ld = '${tools_directory}/ld.lld'
pkgconfig = '/bin/false'

[properties]
c_link_args = ['-pie', '-llog'${linker_flags}]
cpp_link_args = ['-pie', '-llog'${linker_flags}]
c_args = [${compiler_flags}]
cpp_args = ['-fexceptions', '-frtti', ${compiler_flags}]
lua_bindings=false

[host_machine]
system = 'android'
cpu_family = '${architecture}'
cpu = '${cpu}'
endian = 'little'"

	echo "$crossfile" > "crossfiles/${cpu}.txt"
}

function make_files() {
	mkdir -p crossfiles
	mkdir -p wrappers

	make_cross_file arm arm armv7-a androideabi armv7a-linux-androideabi16 "'-Os', '-fPIC', '-mfloat-abi=softfp', '-mfpu=vfpv3-d16', '-mthumb', '-marm', '-march=armv7-a'" ", '-march=armv7-a'"
	make_cross_file arm64 aarch64 armv8-a android aarch64-linux-android21 "'-Os', '-fPIC', '-march=armv8-a'"
	make_cross_file x86 i686 i686 android i686-linux-android16 "'-Os', '-fPIC', '-march=i686', '-mtune=intel', '-msse3', '-mfpmath=sse', '-m32'"
	make_cross_file x86_64 x86_64 westmere android x86_64-linux-android21 "'-Os', '-fPIC', '-march=westmere', '-msse4.2', '-mpopcnt', '-m64', '-mtune=intel'"
}

function delete_files() {
	local cpus=(
		armv6
		armv7-a
		armv8-a
		i686
		westmere
	)

	for cpu in "${cpus[@]}"; do
		rm "${cpu}-cross.txt"
	done
}

case "$1" in
	remove)
		delete_files
		;;
	*)
		make_files
		;;
esac
