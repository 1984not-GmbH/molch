#!/usr/bin/env bash

function make_cross_file() {
	local architecture=$1
	local isa="$2"
	local cpu="$3"
	local abi="$4"
	local compiler_flags="$5"
	local linker_flags="$6"

	local crossfile="[binaries]
c = '${PWD}/${architecture}/bin/clang'
cpp = '${PWD}/${architecture}/bin/workaround-clang++'
strip = '${PWD}/${architecture}/bin/${isa}-linux-${abi}-strip'
ar = '${PWD}/${architecture}/bin/${isa}-linux-${abi}-ar'
ld = '${PWD}/${architecture}/bin/${isa}-linux-${abi}-ld.gold'
pkgconfig = '/usr/bin/false'

[properties]
c_link_args = ['-pie'${linker_flags}]
cpp_link_args = ['-static-libstdc++', '-pie'${linker_flags}]
c_args = [${compiler_flags}]
cpp_args = [${compiler_flags}]
lua_bindings=false

[host_machine]
system = 'android'
cpu_family = '${architecture}'
cpu = '${cpu}'
endian = 'little'"

	echo "$crossfile" > "${cpu}-cross.txt"
}

function make_files() {
	make_cross_file "arm" "arm" "armv6" "androideabi" "'-Os', '-fPIC', '-mthumb', '-marm', '-march=armv6'"
	make_cross_file "arm" "arm" "armv7-a" "androideabi" "'-Os', '-fPIC', '-mfloat-abi=softfp', '-mfpu=vfpv3-d16', '-mthumb', '-marm', '-march=armv7-a'" ", '-march=armv7-a -Wl,--fix-cortex-a8'"
	make_cross_file "arm64" "aarch64" "armv8-a" "android" "'-Os', '-fPIC', '-march=armv8-a'"
	make_cross_file "mips" "mipsel" "mips32" "android" "'-Os', '-fPIC'"
	make_cross_file "mips64" "mips64el" "mips64r6" "android" "'-Os', '-fPIC', '-march=mips64r6'"
	make_cross_file "x86" "i686" "i686" "android" "'-Os', '-fPIC', '-march=i686', '-mtune=intel', '-msse3', '-mfpmath=sse', '-m32'"
	make_cross_file "x86_64" "x86_64" "westmere" "android" "'-Os', '-fPIC', '-march=westmere', '-msse4.2', '-mpopcnt', '-m64', '-mtune=intel'"
}

function delete_files() {
	local cpus=(
		armv6
		armv7-a
		armv8-a
		mips32
		mips64r6
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
