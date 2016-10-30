[![Build Status](https://travis-ci.org/timdaman/check_docker.svg?branch=master)](https://travis-ci.org/timdaman/check_docker)
[![Code Climate](https://codeclimate.com/github/timdaman/check_docker/badges/gpa.svg)](https://codeclimate.com/github/timdaman/check_docker)
[![Test Coverage](https://codeclimate.com/github/timdaman/check_docker/badges/coverage.svg)](https://codeclimate.com/github/timdaman/check_docker/coverage)
# check_docker
This a a nagios/NRPE compatible plugin for checking docker containers. So far you can use it to check

* memory consumption in absolute units (bytes, kb, mb, gb) and as a percent of the container limit.
* automatic restarts performed by the docker daemon
* container status, i.e. is it running?
* uptime, i.e. is it able to stay running for a long enough time?
* image version (experimental!), does the running image match that in the remote registry?

This check can communicate with a local docker daemon socket file (default) or with local or remote docker daemons using secure and non-secure tcp connections.

This plugin requires python 3. It is tested on 3.3 and greater but may work on older versions of 3. 
