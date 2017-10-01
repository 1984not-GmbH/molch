function ninja {
    if [[ ! -z ${MOLCH_CI_PARALLEL+x} ]]; then
        command ninja -j "$MOLCH_CI_PARALLEL" "$@"
    else
        command ninja "$@"
    fi
}
