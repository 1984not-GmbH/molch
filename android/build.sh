#!/usr/bin/env bash

cpu=$1
builddir="build/${cpu}"

mkdir -p "$builddir"
cd "$builddir" || exit 1
meson "../../.." --cross-file "../../crossfiles/${cpu}.txt" --buildtype release -Db_lto=true -Dlua_bindings=false
ninja
