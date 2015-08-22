#!/bin/sh
[[ ! -e static-analysis ]] && mkdir static-analysis
cd static-analysis
scan-build cmake ..
make clean
scan-build make
