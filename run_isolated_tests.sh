#!/usr/bin/env bash
set -eu

(cd testing_tools && docker build -t check_docker_tests .)

docker run --rm -v $PWD:$PWD -w $PWD -ti check_docker_tests detox