#!/usr/bin/env bash

cpu=$1
build_directory="${PWD}/build/${cpu}"
binary_directory="${PWD}/binaries/${cpu}-binaries"
rm -r "$binary_directory"
mkdir -p "$binary_directory"
find "$build_directory" -type f -name '*.so' -exec cp {} "${binary_directory}/" \;
cp "${build_directory}"/test/*-test "${binary_directory}/"
cp "../subprojects/libsodium/libsodium-android-$cpu/lib/libsodium.so" "${binary_directory}/"
rm "${binary_directory}/libprotobuf.so" # This is not used

library_path="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib"

case $cpu in
	armv7-a)
		cp "${library_path}/arm-linux-androideabi/libc++_shared.so" "${binary_directory}/"
		;;

	armv8-a)
		cp "${library_path}/aarch64-linux-android/libc++_shared.so" "${binary_directory}/"
		;;

	westmere)
		cp "${library_path}/x86_64-linux-android/libc++_shared.so" "${binary_directory}/"
		;;

	i686)
		cp "${library_path}/i686-linux-android/libc++_shared.so" "${binary_directory}/"
		;;

	*)
		echo "UNKNOWN CPU ARCHITECTURE, FAILED TO COPY libc++_shared.so"
		exit 1
esac
