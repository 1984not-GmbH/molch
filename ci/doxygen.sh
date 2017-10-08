#!/bin/bash
basedir=$(dirname "$0")
cd "$basedir/.." || exit 1

doxygen
