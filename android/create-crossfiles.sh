#!/usr/bin/env bash

function make_cross_file() {
	local architecture=$1
	local cpu="$2"
	local flags="$3"

	local crossfile="[binaries]
c = '${PWD}/${architecture}/bin/clang'
cpp = '${PWD}/${architecture}/bin/workaround-clang++'
strip = '${PWD}/${architecture}/bin/arm-linux-androideabi-strip'
ar = '${PWD}/${architecture}/bin/arm-linux-androideabi-ar'
ld = '${PWD}/${architecture}/bin/arm-linux-androideabi-ld.gold'
pkgconfig = '/usr/bin/false'

[properties]
c_link_args = ['-pie']
cpp_link_args = ['-static-libstdc++', '-pie']
c_args = [${flags}]
cpp_args = [${flags}]
lua_bindings=false

[host_machine]
system = 'android'
cpu_family = '${architecture}'
cpu = '${cpu}'
endian = 'little'"

	echo "$crossfile" > "${cpu}-cross.txt"
}

function make_files() {
	make_cross_file "arm" "armv6" "'-Os', '-fPIC', '-mthumb', '-marm', '-march=armv6'"
	make_cross_file "arm" "armv7-a" "'-Os', '-fPIC', -mfloat-abi=softfp', '-mfpu=vfpv3-d16', '-mthumb', '-marm', '-march=armv7-a'"
	make_cross_file "arm64" "armv8-a" "'-Os', '-fPIC', '-march=armv8-a'"
	make_cross_file "mips32" "mips32" "'-Os', '-fPIC'"
	make_cross_file "mips64" "mips64r6" "'-Os', '-fPIC', '-march=mips64r6'"
	make_cross_file "x86" "i686" "'-Os', '-fPIC', '-march=i686'"
	make_cross_file "x86_64" "westmere" "'-Os', '-fPIC', '-march=westmere'"
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
