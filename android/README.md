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
1. Create the meson cross compilation files: Run `./create-crossfiles.sh` in this directory. If you want to remove these files, run `./create-crossfiles.sh remove`
2. Do the cross build: Run `./build.sh` followed by the CPU architecture (the prefixes of the cross files). Alternatively you can build all of them with `./build-all.sh`.
3. Collect the binaries with `./collect-binaries.sh` followed by the CPU architecture. Alternatively you can collect all of them with `./collect-all.sh`. These can now be used in an Android Application.
