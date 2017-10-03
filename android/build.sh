#!/usr/bin/env bash

cpu=$1
builddir="${cpu}-build"

mkdir -p "$builddir"
cd "$builddir" || exit 1
meson ../.. --cross-file "../${cpu}-cross.txt" --buildtype release -Db_lto=true -Dlua_bindings=false
ninja
