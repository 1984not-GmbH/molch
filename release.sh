#!/bin/bash
basedir=$(dirname "$0")
source "$basedir/ci/ninja.sh" || exit 1

lua_bindings="true"
if [[ ! -z ${MOLCH_CI_DISABLE_LUA+x} ]]; then
    echo "Lua bindinds are disabled!"
    lua_bindings="false"
fi

output_dir="release"
[[ -e "$output_dir" ]] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
if [[ ! -e "$output_dir" ]]; then
    meson --buildtype release -Db_lto=true -Dlua_bindings="$lua_bindings" .. || exit 1
fi

ninja
ninja test
DESTDIR="$output_dir/installation" ninja install
