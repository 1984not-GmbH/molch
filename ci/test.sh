#!/bin/bash
output_dir=build
[ -e build ] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
if meson ..; then
    # This has to be done with else because with '!' it won't work on Mac OS X
    true
else
    exit $? #abort on failure
fi

if ninja test; then
    true
else
    exit $?
fi

if hash valgrind 2> /dev/null; then
    if meson test --setup valgrind; then
        true
    else
        exit $?
    fi
else
    true
fi
