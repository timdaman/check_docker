
if [ ! -f /etc/alpine-release ]
then
    echo "This is only intended to be run inside a vagrant box!" >&2
    echo "Running it outside may result in data loss" >&2
    exit 1
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
}


load bats_fixtures


@test "Confirm check_docker is not in path" {

    # Before we start make sure check_docker is not present
    sudo pip3 uninstall -y check-docker || true
    run which check_docker
    [ "$status" -eq 1 ]
}

@test "Confirm 'check-docker' is not installed" {

    # Before we start make sure check_docker is not present
    pip3 list 2>&1 | grep -ve check-docker
}

@test "Confirm source package, $NEWEST_SDIST, is installable" {

    run sudo pip3 install "$NEWEST_SDIST"
    [ "$status" -eq 0 ]
}

@test "Re-Confirm 'check-docker' is not installed" {

    # This should never error since the previous step ensures package is already present
    sudo pip3 uninstall -y check-docker
    # Before we start make sure check_docker is not present
    pip3 list 2>&1 | grep -ve check-docker
}

@test "Confirm wheel package, $NEWEST_WHEEL, is installable" {

    run sudo pip3 install "$NEWEST_WHEEL"
    [ "$status" -eq 0 ]
}

@test "Confirm check_docker appears in path" {
    run which check_docker
    [ "$status" -eq 0 ]
}

@test "Confirm package is installed" {
    pip3 list |  grep 'check-docker'
}

# It is normal for this to fail when preparing for a PR.
@test "Confirm package version is not already in PyPi" {
    VERSION=$(get_check_docker_version)
    REMOTE_HTTP_STATUS=$(curl -LI https://pypi.org/project/check_docker/${VERSION}/ -w "%{http_code}" -o /dev/null -s)
    [ "$REMOTE_HTTP_STATUS" == 404 ]
}

@test "Confirm check_docker version matches package" {
    PACKAGE_VERSION=$(get_check_docker_version)
    CHECK_VERSION=$(python3 -c 'from check_docker import check_docker; print(check_docker.__version__)')

    [ "$PACKAGE_VERSION" == "$CHECK_VERSION" ]
}

@test "Confirm check_swarm version matches package" {
    PACKAGE_VERSION=$(get_check_docker_version)
    CHECK_VERSION=$(python3 -c 'from check_docker import check_swarm; print(check_swarm.__version__)')

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

SITE_PACKAGES_DIR=/usr/lib/python3.6/site-packages/check_docker
@test "Can check_docker be run when called directly" {
    good_container

    run python3 $SITE_PACKAGES_DIR/check_docker.py --help
    [ "$status" -eq 0 ]
}

@test "Can check_swarm be run when called directly" {
    good_container

    run python3 $SITE_PACKAGES_DIR/check_swarm.py --help
    [ "$status" -eq 0 ]

}