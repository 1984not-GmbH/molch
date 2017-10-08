#!/bin/bash
basedir=$(dirname "$0")
cd "$basedir/.." || exit 1
source "ci/ninja.sh" || exit 1

lua_bindings="true"
if [[ ! -z ${MOLCH_CI_DISABLE_LUA+x} ]]; then
    echo "Lua bindinds are disabled!"
    lua_bindings="false"
fi

export CC=clang
export CXX=clang++

output_dir=build-clang
[[ -e "$output_dir" ]] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
meson .. -Dlua_bindings="$lua_bindings" || exit $?

meson test --print-errorlogs
