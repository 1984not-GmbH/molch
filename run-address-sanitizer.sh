#!/bin/sh
[[ ! -e address-sanitizer ]] && mkdir address-sanitizer
cd address-sanitizer
cmake .. -DCMAKE_C_FLAGS='-fsanitize=address'
make clean
make
make test
