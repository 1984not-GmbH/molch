#!/bin/bash
basedir=$(dirname "$0")
TESTS=("release.sh" "ci/test.sh" "ci/clang.sh" "ci/static-analysis.sh" "ci/sanitizers.sh" "ci/doxygen.sh")
STATUS="OK"

for TEST in "${TESTS[@]}"; do
    echo "$TEST"
    if ! "$basedir/$TEST"; then
        STATUS="FAILED"
    fi
done

case $STATUS in
    "OK")
        exit 0
        ;;
    "FAILED")
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
