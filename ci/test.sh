#!/bin/bash
basedir=$(dirname "$0")
cd "$basedir/.." || exit 1
source "ci/ninja.sh" || exit 1

function valgrind_works {
    if ! hash valgrind 2> /dev/null; then
        return 1
    fi


    local output_name=valgrind_works-test
    echo -e "#include <stdio.h>\n int main() {puts(\"Hello World!\");}" > "$output_name".c
    gcc "$output_name".c -o "$output_name"

    valgrind --suppressions=../valgrind.supp ./"$output_name" 2> /dev/null
    local result=$?
    rm "$output_name"{,.c}
    return $result
}

lua_bindings="true"
if [[ ! -z ${MOLCH_CI_DISABLE_LUA+x} ]]; then
    echo "Lua bindinds are disabled!"
    lua_bindings="false"
fi

output_dir=build
[[ -e "$output_dir" ]] && rm -r "$output_dir"
mkdir "$output_dir"
cd "$output_dir" || exit 1
meson .. -Dlua_bindings="$lua_bindings" || exit $?

meson test --print-errorlogs || exit $?

if valgrind_works; then
    meson test --setup valgrind --print-errorlogs || exit $?
else
    echo "Valgrind doesn't work!"
    true
fi
