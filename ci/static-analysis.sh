#!/bin/bash
basedir=$(dirname "$0")
cd "$basedir/.." || exit 1
source "ci/ninja.sh" || exit 1

if ! hash scan-build; then
    echo Clang static analyzer not installed. Skipping ...
    exit 0
fi
output_dir=static-analysis
[[ -e "$output_dir" ]] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
if meson .. -Denable_old_java_bindings=false; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    echo
else
    exit $? #abort on failure
fi
ninja scan-build
