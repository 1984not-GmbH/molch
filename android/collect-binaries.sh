#!/usr/bin/env bash

cpu=$1
cd "$cpu-build" || exit 1
rm -r binaries
mkdir -p binaries
find . -type f -name '*.so' -exec cp {} binaries/ \;
cp test/*-test binaries/
cp "../../subprojects/libsodium/$cpu/libsodium.so" binaries/
rm "binaries/libprotobuf.so"

case $cpu in
	armv6)
		cp ../arm/arm-linux-androideabi/lib/armv7-a/thumb/libc++_shared.so binaries/
		;;
	armv7-a)
		cp ../arm/arm-linux-androideabi/lib/armv7-a/thumb/libc++_shared.so binaries/
		;;

	armv8-a)
		cp ../arm64/aarch64-linux-android/lib/libc++_shared.so binaries/
		;;

	westmere)
		cp ../x86_64/x86_64-linux-android/lib64/libc++_shared.so binaries/
		;;

	i686)
		cp ../x86/i686-linux-android/lib/libc++_shared.so binaries/
		;;

	*)
		echo "UNKNOWN CPU ARCHITECTURE, FAILED TO COPY libc++_shared.so"
		exit 1
esac
