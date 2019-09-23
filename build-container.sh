#!/usr/bin/env bash

./stop-and-remove-container.sh
docker build . -t molch:latest -t molch:$(date +%F-%H-%M-%S)
