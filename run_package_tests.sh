#!/usr/bin/env bash

set -eux

cd testing_tools/vagrant
vagrant up
vagrant ssh -c "bats -p /check_docker/testing_tools/vagrant"
vagrant suspend
