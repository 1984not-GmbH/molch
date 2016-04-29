#!/bin/bash
[ ! -e build ] && mkdir build
RETURN_VALUE=0
cd build
if cmake ..; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    echo
else
    exit $? #abort on failure
fi
make clean
if make; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    echo
else
    exit $? #abort on failure
fi
export CTEST_OUTPUT_ON_FAILURE=1
make test
