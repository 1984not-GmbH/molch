#!/bin/sh
[ ! -e static-analysis ] && mkdir static-analysis
cd static-analysis
scan-build --status-bugs cmake ..
make clean
scan-build --status-bugs make
