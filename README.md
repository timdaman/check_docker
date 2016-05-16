# check_docker
This a a nagios/NRPE compatible plugin for checking docker containers. So far you can use it to check

* memory consumption in absolute units (bytes, kb, mb, gb) and as a percent of the container limit.
* automatic restarts performed by the docker daemon
* container status, i.e. is it running?

This check can communicate with a local docker daemon socket file (default) or with local or remote docker daemons using secure and non-secure tcp connections.
