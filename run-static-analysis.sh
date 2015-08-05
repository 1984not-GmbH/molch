#!/bin/sh
[[ ! -e static-analysis ]] && mkdir static-analysis
cd static-analysis
echo "Recursively remove '$PWD/*'?"
rm -rI *
scan-build cmake ..
scan-build make
