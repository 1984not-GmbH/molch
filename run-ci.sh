#!/bin/bash
basedir=$(dirname "$0")
cd "$basedir" || exit 1

TESTS=("release.sh" "ci/test.sh" "ci/clang.sh" "ci/clang-tidy.sh" "ci/static-analysis.sh" "ci/sanitizers.sh" "ci/doxygen.sh")
STATUS="OK"

FAILED_TESTS=""
for TEST in "${TESTS[@]}"; do
    echo "$TEST"
    if ! "./$TEST"; then
        STATUS="FAILED"
        FAILED_TESTS="${FAILED_TESTS}${TEST};"
    fi
done

case $STATUS in
    "OK")
        exit 0
        ;;
    "FAILED")
        echo "Failed tests: $FAILED_TESTS"
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
