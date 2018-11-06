#!/usr/bin/env bash

./collect-binaries.sh armv6 || exit 1
./collect-binaries.sh armv7-a || exit 1
./collect-binaries.sh armv8-a || exit 1
./collect-binaries.sh westmere || exit 1
./collect-binaries.sh i686 || exit 1
