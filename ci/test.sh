#!/bin/sh
[ ! -e build ] && mkdir build
RETURN_VALUE=0
cd build
if ! cmake ..; then
    exit $? #abort on failure
fi
make clean
if ! make; then
    exit $? #abort on failure
fi
make test
