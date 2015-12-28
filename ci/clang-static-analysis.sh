#!/bin/sh
if ! hash scan-build; then
    echo Clang static analyzer not installed. Skipping ...
    exit 0
fi
[ ! -e static-analysis ] && mkdir static-analysis
cd static-analysis
if ! scan-build --status-bugs cmake .. -DCMAKE_BUILD_TYPE=Debug; then
    exit $? #abort on failure
fi
make clean
scan-build --status-bugs make
