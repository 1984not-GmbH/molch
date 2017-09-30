Cross Compiling For Android
===========================

Prerequisites
-------------
* Android-NDK
* Environment variable `ANDROID_NDK_HOME` set.
* GNU/Linux host system. (might work on Mac OS and BSDs as well, not sure)
* Meson

Steps
-----
1. Create the standalone toolchains: Run `./toolchains.sh` in this directory. If you want to remove the toolchains, run `./toolchains.sh remove`
2. Create the meson cross compilation files: Run `./create-crossfiles.sh` in this directory. If you want to remove these files, run `./create-crossfiles.sh remove`
3. Build libsodium android binaries and put them in `subprojects/`
4. Do the cross build: Run `./build.sh` followed by the CPU architecture (the prefixes of the cross files).
5. Now collect the newly built libraries `libmolch.so`, `libprotobuf-c.so` and the appropriate `libc++_shared.so` from the toolchain as well as the appropriate `libsodium.so` for the architecture and put all of them together. These can now be used in an Android Application.
