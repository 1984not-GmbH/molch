#!/usr/bin/env bash

function make_toolchain() {
	local architecture=$1
	local api_level=$2
	local make_toolchain_command="${ANDROID_NDK_HOME}/build/tools/make_standalone_toolchain.py"

	echo "Creating standalone toolchain for $architecture"
	"$make_toolchain_command" --arch "$architecture" --api "$api_level" --stl libc++ --install-dir "$architecture"

	cp meson-workaround-clang-wrapper.sh "$architecture/bin/workaround-clang++"
}

API_LEVEL32=16
ARCHITECTURES32=(
	arm
	mips
	x86
)

API_LEVEL64=21
ARCHITECTURES64=(
	arm64
	mips64
	x86_64
)

case $1 in
	remove)
		for arch in "${ARCHITECTURES32[@]}" "${ARCHITECTURES64[@]}"; do
			echo "Removing standalone toolchain for $arch"
			rm -r "$arch"
		done
		;;

	*)
		for arch in "${ARCHITECTURES32[@]}"; do
			make_toolchain "$arch" "$API_LEVEL32"
		done

		for arch in "${ARCHITECTURES64[@]}"; do
			make_toolchain "$arch" "$API_LEVEL64"
		done
		;;
esac
