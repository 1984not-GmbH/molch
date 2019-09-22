#!/usr/bin/env bash

cpu=$1
cd "$cpu-build" || exit 1
rm -r binaries
mkdir -p binaries
find . -type f -name '*.so' -exec cp {} binaries/ \;
cp test/*-test binaries/
cp "../../subprojects/libsodium/$cpu/lib/libsodium.so" binaries/
rm "binaries/libprotobuf.so"

case $cpu in
	armv6)
		cp ../arm/sysroot/usr/lib/arm-linux-androideabi/libc++_shared.so binaries/
		;;
	armv7-a)
		cp ../arm/sysroot/usr/lib/arm-linux-androideabi/libc++_shared.so binaries/
		;;

	armv8-a)
		cp ../arm64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so binaries/
		;;

	westmere)
		cp ../x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so binaries/
		;;

	i686)
		cp ../x86/sysroot/usr/lib/i686-linux-android/libc++_shared.so binaries/
		;;

	*)
		echo "UNKNOWN CPU ARCHITECTURE, FAILED TO COPY libc++_shared.so"
		exit 1
esac
