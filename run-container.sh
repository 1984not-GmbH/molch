#!/usr/bin/env bash
docker run --name molch_builder -it molch:latest bash && exit 0
docker start molch_builder
docker exec -it molch_builder bash
