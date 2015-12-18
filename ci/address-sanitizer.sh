#!/bin/sh
[ ! -e address-sanitizer ] && mkdir address-sanitizer
cd address-sanitizer
#check if address sanitizer is available
echo "int main(void) {return 0;}" > test.c
if ! clang -fsanitize=address test.c -o /dev/null > /dev/null; then
    echo AddressSanitizer not available. Skipping ...
    rm test.c
    exit 0
fi
rm test.c

export CC=clang
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-fsanitize=address -O1 -fno-omit-frame-pointer -fno-common -fno-optimize-sibling-calls -g' -DDISABLE_MEMORYCHECK_COMMAND="TRUE"
make clean
make
export ASAN_OPTIONS="$ASAN_OPTIONS:detect_stack_use_after_return=1:check_initialization_order=1"
make test
