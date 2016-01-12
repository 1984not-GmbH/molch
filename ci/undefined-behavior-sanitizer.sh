#!/bin/sh
[ ! -e undefined-behavior-sanitizer ] && mkdir undefined-behavior-sanitizer
cd undefined-behavior-sanitizer
#check if undefined-behavior sanitizer is available
echo "int main(void) {return 0;}" > test.c
if ! clang -fsanitize="undefined,integer" test.c -o /dev/null > /dev/null; then
    echo UndefinedBehaviorSanitizer not available. Skipping ...
    rm test.c
    exit 0
fi
rm test.c

export CC=clang
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-fsanitize=undefined,integer -fno-sanitize-recover=undefined,integer -O1 -fno-omit-frame-pointer -fno-common -fno-optimize-sibling-calls -g' -DDISABLE_MEMORYCHECK_COMMAND="TRUE"
make clean
make
make test
