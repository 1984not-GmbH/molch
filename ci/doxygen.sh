#!/bin/bash
[ ! -e dummy ] && mkdir dummy

cd dummy
cmake .. -DGENERATE_DOC=On
