#!/bin/sh
TESTS=("ci/test.sh" "ci/clang-static-analysis.sh" "ci/address-sanitizer.sh")
STATUS="OK"

for TEST in ${TESTS[@]}; do
    echo $TEST
    "$TEST"
    if [ ! $? -eq 0 ]; then
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
