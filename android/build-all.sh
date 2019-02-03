#!/usr/bin/env bash

./create-crossfiles.sh
./build.sh armv6 || exit 1
./build.sh armv7-a || exit 1
./build.sh armv8-a || exit 1
./build.sh westmere || exit 1
./build.sh i686 || exit 1
