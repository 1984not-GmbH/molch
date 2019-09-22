#!/usr/bin/env bash
cd android
rm -rf build crossfiles wrappers binaries
./create-crossfiles.sh
./build-all.sh
./collect-all.sh
