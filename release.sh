#!/bin/bash
output_dir="release"
if [ ! -e "$output_dir" ]; then
    meson --buildtype release "$output_dir" || exit 1
fi

cd "$output_dir" || exit 1
ninja
ninja test
