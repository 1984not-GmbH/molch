#!/bin/sh
if [ $(uname) == "Darwin" ]; then
    #Skip test on Mac OS X
    #TODO Make this work!
    exit 0
fi
[ ! -e address-sanitizer ] && mkdir address-sanitizer
cd address-sanitizer
cmake .. -DCMAKE_C_FLAGS='-fsanitize=address -O1 -fno-omit-frame-pointer -fno-common -fno-optimize-sibling-calls -g' -DDISABLE_MEMORYCHECK_COMMAND="TRUE"
make clean
make
export ASAN_OPTIONS="$ASAN_OPTIONS:detect_stack_use_after_return=1"
make test
