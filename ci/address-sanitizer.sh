#!/bin/bash
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
if cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-fsanitize=address -O1 -fno-omit-frame-pointer -fno-common -fno-optimize-sibling-calls -g' -DDISABLE_MEMORYCHECK_COMMAND="TRUE"; then
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
export ASAN_OPTIONS="$ASAN_OPTIONS:detect_stack_use_after_return=1:check_initialization_order=1"
export CTEST_OUTPUT_ON_FAILURE=1
make test
