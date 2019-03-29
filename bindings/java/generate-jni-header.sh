#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"
cd "$script_directory/src/main/java/de/nineteen/eighty/four/not/molch"

javac -h "$script_directory" Molch.java
