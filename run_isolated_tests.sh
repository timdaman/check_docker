#!/usr/bin/env bash
COMPOSE_CMD="docker-compose --project-directory ./  -f testing_tools/isolated_tests.yaml"

$COMPOSE_CMD build
for test_environment in $($COMPOSE_CMD config --services)
do
    printf '\n====================\nRunning %s \n====================\n\n' "$test_environment"
    $COMPOSE_CMD run --rm "$test_environment"
done