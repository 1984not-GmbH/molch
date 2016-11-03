#!/bin/bash
[ ! -e dummy ] && mkdir dummy

cd dummy || exit 1
cmake .. -DGENERATE_DOC=On
