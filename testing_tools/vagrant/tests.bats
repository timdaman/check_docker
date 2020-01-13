
if ! id vagrant
then
    echo "This is only intended to be run inside a vagrant box!" >&2
    echo "Running it outside may result in data loss" >&2
fi

NEWEST_SDIST="$(ls -t /check_docker/dist/check_docker-*.tar.gz | head -1)"
NEWEST_WHEEL="$(ls -t /check_docker/dist/check_docker-*.whl | head -1)"

teardown()
{
    docker ps -aq
    COUNT=$(docker ps -aq | wc -l)
    if [ $COUNT -ne 0 ]
    then
        docker stop -t 0 $(docker ps -aq)
        docker rm -f $(docker ps -aq)
    fi
    STACKS=$(docker stack ls)
    if grep -q TEST_STACK <<<"$STACKS"
    then
        docker stack rm TEST_STACK
        TEST_CONTAINERS_COUNT=$(docker ps | grep TEST_STACK | wc -l)
        while [ $TEST_CONTAINERS_COUNT -ne 0 ]
        do
            sleep 1
            TEST_CONTAINERS_COUNT=$(docker ps | grep TEST_STACK | wc -l)
        done

        TEST_NETWORK_COUNT=$(docker network ls | grep TEST_STACK | wc -l)
        while [ $TEST_NETWORK_COUNT -ne 0 ]
        do
            sleep 1
            TEST_NETWORK_COUNT=$(docker network ls | grep TEST_STACK | wc -l)
        done
    fi
}


load bats_fixtures


@test "Confirm check_docker is not in path" {

    # Before we start make sure check_docker is not present
    sudo -H pip3.8 uninstall -y check-docker || true
    run which check_docker
    [ "$status" -eq 1 ]
}

@test "Confirm 'check-docker' is not installed" {

    # Before we start make sure check_docker is not present
    pip3.8 list 2>&1 | grep -ve check-docker
}

@test "Confirm source package, $NEWEST_SDIST, is installable" {
    echo pip3.8 install "$NEWEST_SDIST"
    run sudo -H pip3.8 install "$NEWEST_SDIST"
    [ "$status" -eq 0 ]
}

@test "Re-Confirm 'check-docker' is not installed" {

    # This should never error since the previous step ensures package is already present
    sudo -H pip3.8 uninstall -y check-docker
    # Before we start make sure check_docker is not present
    pip3.8 list 2>&1 | grep -ve check-docker
}

@test "Confirm wheel package, $NEWEST_WHEEL, is installable" {

    run sudo -H pip3.8 install "$NEWEST_WHEEL"
    [ "$status" -eq 0 ]
}

@test "Confirm check_docker appears in path" {
    run which check_docker
    [ "$status" -eq 0 ]
}

@test "Confirm package is installed" {
    pip3.8 list |  grep 'check-docker'
}

# It is normal for this to fail when preparing for a PR.
@test "Confirm package version is not already in PyPi" {
    VERSION=$(get_check_docker_version)
    REMOTE_HTTP_STATUS=$(curl -LI https://pypi.org/project/check_docker/${VERSION}/ -w "%{http_code}" -o /dev/null -s)
    [ "$REMOTE_HTTP_STATUS" == 404 ]
}

@test "Confirm check_docker version matches package" {
    PACKAGE_VERSION=$(get_check_docker_version)
    CHECK_VERSION=$(python3.8 -c 'from check_docker import check_docker; print(check_docker.__version__)')

    [ "$PACKAGE_VERSION" == "$CHECK_VERSION" ]
}

@test "Confirm check_swarm version matches package" {
    PACKAGE_VERSION=$(get_check_docker_version)
    CHECK_VERSION=$(python3.8 -c 'from check_docker import check_swarm; print(check_swarm.__version__)')

    [ "$PACKAGE_VERSION" == "$CHECK_VERSION" ]
}

@test "Good status" {
    good_container
    sleep 1
    run check_docker --container good_sleep --status running
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
}

@test "Bad status" {
    bad_container
    run check_docker --container bad_sleep --status running
    echo "$status"
    echo $output
    [ "$status" -eq 2 ]
}

@test "Current version" {
    docker pull busybox
    current_container
    run check_docker --container current_container --version
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
}

@test "Old version" {
    old_container
    run check_docker --container old_container --version
    echo "$status"
    echo $output
    [ "$status" -eq 2 ]
}

@test "Doesn't crash" {
    good_container
    sleep 5
    run check_docker --container good_sleep --restarts 1:2
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
}

@test "Does crash" {
    crashing_container
    sleep 5
    run check_docker --container crashes --restarts 1:2
    echo "$status"
    echo $output
    [ "$status" -eq 2 ]
}

@test "Checks multiple containers" {
    good_container
    current_container
    run check_docker --container good_sleep current_container  --status running
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
}

@test "Checks multiple containers regex" {
    good_container
    current_container
    run check_docker --container '.*'  --status running
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
}

@test "Checks get all containers" {
    good_container
    current_container
    run check_docker --container '.*'  --status running
    echo "$status"
    echo $output
    [ "$status" -eq 0 ]
    CONTIANERS_IN_CHECK=$(echo $output | tr ';' '\n' | wc -l)
    [ "$CONTIANERS_IN_CHECK" -eq 2 ]

}

SITE_PACKAGES_DIR=/$(pip3.8 show check_docker | grep '^Location' | cut -d ' '  -f 2)/check_docker
@test "Can check_docker be run when called directly" {

    run python3.8 $SITE_PACKAGES_DIR/check_docker.py --help
    [ "$status" -eq 0 ]
}

@test "Can check_swarm be run when called directly" {

    run python3.8 $SITE_PACKAGES_DIR/check_swarm.py --help
    [ "$status" -eq 0 ]

}

@test "Confirm replicated service failures are noticed" {
  cat <<END | docker stack deploy -c - TEST_STACK
version: "3"
services:
  test:
    image: busybox
    command: "false"
    deploy:
      mode: replicated
      replicas: 2
END

    sleep 1
    run check_swarm --service TEST_STACK
    [ "$status" -eq 2 ]
}

@test "Confirm global service failures are noticed" {
cat <<END | docker stack deploy -c - TEST_STACK
version: "3"
services:
  test:
    image: busybox
    command: "false"
    deploy:
      mode: global
END
    sleep 1

    run check_swarm --service TEST_STACK
    [ "$status" -eq 2 ]

}

@test "Confirm global service succeed" {
  cat <<END | docker stack deploy -c - TEST_STACK
version: "3"
services:
  test:
    image: busybox
    command: sleep 100
    deploy:
      mode: replicated
      replicas: 2
END
    sleep 5

    run check_swarm --service TEST_STACK_test
    echo $OUTPUT
    [ "$status" -eq 0 ]
}

@test "Confirm replicated service succeed" {
    echo BEFORE
    docker ps
    docker network ls
  cat <<END | docker stack deploy -c - TEST_STACK
version: "3"
services:
  test:
    image: busybox
    command: sleep 100
    deploy:
      mode: replicated
      replicas: 2
END
    sleep 5

    echo AFTER
    docker ps -a
    docker network ls
    docker service ls
    run check_swarm --service TEST_STACK_test
    echo $output
    [ "$status" -eq 0 ]
}
