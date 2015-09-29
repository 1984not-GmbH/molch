#!/bin/sh
[ ! -e build ] && mkdir build
RETURN_VALUE=0
cd build
cmake ..
make clean
make
if [ ! $? -eq 0 ]; then
    echo Build failed
    RETURN_VALUE=1
fi
make test
if [ ! $? -eq 0 ]; then
    echo Tests failed
    RETURN_VALUE=1
fi
exit $RETURN_VALUE
