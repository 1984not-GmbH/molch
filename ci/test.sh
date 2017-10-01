#!/bin/bash
function valgrind_works {
    if ! hash valgrind 2> /dev/null; then
        return 1
    fi


    local output_name=valgrind_works-test
    echo -e "#include <stdio.h>\n int main() {puts(\"Hello World!\");}" > "$output_name".c
    gcc "$output_name".c -o "$output_name"

    valgrind --suppressions=../valgrind.supp ./"$output_name" #2> /dev/null
    local result=$?
    rm "$output_name"{,.c}
    return $result
}

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

if valgrind_works; then
    if meson test --setup valgrind; then
        true
    else
        exit $?
    fi
else
    echo "Valgrind doesn't work!"
    true
fi
