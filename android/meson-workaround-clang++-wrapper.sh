#!/usr/bin/env bash

# This is a wrapper around the compiler that undefines _FILE_OFFSET_BITS.
# This is necessary for compiling C++ code with Meson, since it stupidly sets _FILE_OFFSET_BITS=64 without any apparent way of turning it off
"$(dirname "$0")/clang++" "$@" -U_FILE_OFFSET_BITS
