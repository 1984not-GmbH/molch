#!/bin/bash
basedir=$(dirname "$0")
source "$basedir/ninja.sh" || exit 1

export CC=clang
export CXX=clang++

output_dir=clang-tidy
if [[ "$1" != "tidy-only" ]]; then
    [[ -e "$output_dir" ]] && rm -r "$output_dir"
    mkdir "$output_dir"
    cd "$output_dir" || exit 1
    if meson .. --buildtype plain -Dlua_bindings=false; then
        # This has to be done with else because with '!' it won't work on Mac OS X
        true
    else
        exit $? #abort on failure
    fi

    ninja

    sed -i 's/-pipe//g' compile_commands.json
else
    cd "$output_dir" || exit 1
fi

clang-tidy -p='.' '../lib/'*.cpp '../test/'*.cpp -checks='-clang-diagnostic-*,modernize-*,-modernize-raw-string-literal,-modernize-pass-by-value' -warnings-as-errors='*' -header-filter='(.*lib/.*\\.h(pp)?|.*test/.*\\.h(pp)?)'
