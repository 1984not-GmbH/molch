#!/bin/bash
if ! hash scan-build; then
    echo Clang static analyzer not installed. Skipping ...
    exit 0
fi
output_dir=static-analysis
[ -e "$output_dir" ] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
if meson ..; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    echo
else
    exit $? #abort on failure
fi
ninja scan-build
