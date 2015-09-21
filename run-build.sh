#!/bin/sh
[[ ! -e build ]] && mkdir build
cd build
cmake ..
make
RETURN_VALUE=$?
echo "NOTE: If you run into problems, first try to delete everything in the build directory and run the build again."
exit $RETURN_VALUE
