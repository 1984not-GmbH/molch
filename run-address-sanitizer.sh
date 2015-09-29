#!/bin/sh
[[ ! -e address-sanitizer ]] && mkdir address-sanitizer
cd address-sanitizer
cmake .. -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls -g' -DDISABLE_MEMORYCHECK_COMMAND="TRUE"
make clean
make
make test
