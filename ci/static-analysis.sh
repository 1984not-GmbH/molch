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
meson .. || exit $?
ninja scan-build
