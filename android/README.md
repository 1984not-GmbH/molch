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
