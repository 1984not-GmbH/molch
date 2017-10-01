#!/bin/bash
basedir=$(dirname "$0")
source "$basedir/ninja.sh" || exit 1

if [[ ! -z ${MOLCH_CI_DISABLE_SANITIZERS+x} ]]; then
    echo "Sanitizers are disabled!"
    exit 0
fi

output_dir="sanitizers"
[[ -e "$output_dir" ]] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
#check if address sanitizer is available
echo "int main(void) {return 0;}" > test.c
if ! gcc -fsanitize=address,undefined test.c -o sanitizers-test > /dev/null || ! ./sanitizers-test; then
    echo AddressSanitizer not available or doesn\'t work. Skipping ...
    rm test.c sanitizers-test
    exit 0
fi
rm test.c sanitizers-test

if meson .. -Db_sanitize=address,undefined; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    true
else
    exit $? #abort on failure
fi
export ASAN_OPTIONS="$ASAN_OPTIONS:detect_stack_use_after_return=1:check_initialization_order=1"
export CTEST_OUTPUT_ON_FAILURE=1
ninja test
