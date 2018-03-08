|Build Status| |Code Climate| |Test Coverage|


============
check_docker
============

Nagios/NRPE compatible plugins for checking docker based services. Currently there are two nagios checks

-  `check_docker` which checks docker container health
-  `check_swarm` which checks health of swarm nodes and services

With check_docker can use it to check and alert on

-  memory consumption in absolute units (bytes, kb, mb, gb) and as a percentage (0-100%)
   of the container limit.
-  CPU usages as a percentage (0-100%) of container limit.
-  automatic restarts performed by the docker daemon
-  container status, i.e. is it running?
-  container health checks are passing?
-  uptime, i.e. is it able to stay running for a long enough time?
-  the presence of a container or containers matching specified names
-  image version, does the running image match that in the remote registry?

With check_swarm you can alert

-  if a node is not joined to a docker swarm
-  if a service is running in a swarm

These checks can communicate with a local docker daemon socket file (default) or with local
or remote docker daemons using secure and non-secure TCP connections.

These plugins require python 3. It is tested on 3.3 and greater but may work on older
versions of 3.

check_docker Usage
------------------

::

usage: check_docker [-h]
                    [--connection [/<path to>/docker.socket|<ip/host address>:<port>]
                    | --secure-connection [<ip/host address>:<port>]]
                    [--binary_units | --decimal_units] [--timeout TIMEOUT]
                    [--containers CONTAINERS [CONTAINERS ...]] [--present]
                    [--cpu WARN:CRIT] [--memory WARN:CRIT:UNITS]
                    [--status STATUS] [--health] [--uptime WARN:CRIT]
                    [--version]
                    [--insecure-registries INSECURE_REGISTRIES [INSECURE_REGISTRIES ...]]
                    [--restarts WARN:CRIT]

Check docker containers.

optional arguments:
  -h, --help            show this help message and exit
  --connection [/<path to>/docker.socket|<ip/host address>:<port>]
                        Where to find docker daemon socket. (default:
                        /var/run/docker.sock)
  --secure-connection [<ip/host address>:<port>]
                        Where to find TLS protected docker daemon socket.
  --binary_units        Use a base of 1024 when doing calculations of KB, MB,
                        GB, & TB (This is default)
  --decimal_units       Use a base of 1000 when doing calculations of KB, MB,
                        GB, & TB
  --timeout TIMEOUT     Connection timeout in seconds. (default: 10.0)
  --containers CONTAINERS [CONTAINERS ...]
                        One or more RegEx that match the names of the
                        container(s) to check. If omitted all containers are
                        checked. (default: ['all'])
  --present             Modifies --containers so that each RegEx must match at
                        least one container.
  --cpu WARN:CRIT       Check cpu usage percentage taking into account any
                        limits. Valid values are 0 - 100.
  --memory WARN:CRIT:UNITS
                        Check memory usage taking into account any limits.
                        Valid values for units are %,B,KB,MB,GB.
  --status STATUS       Desired container status (running, exited, etc).
                        (default: None)
  --health              Check container's health check status
  --uptime WARN:CRIT    Minimum container uptime in seconds. Use when
                        infrequent crashes are tolerated.
  --version             Check if the running images are the same version as
                        those in the registry. Useful for finding stale
                        images. Does not support login.
  --insecure-registries INSECURE_REGISTRIES [INSECURE_REGISTRIES ...]
                        List of registries to connect to with http(no TLS).
                        Useful when using "--version" with images from
                        insecure registries.
  --restarts WARN:CRIT  Container restart thresholds.

check_swarm Usage
-----------------

::

  usage: check_swarm [-h]
                     [--connection [/<path to>/docker.socket|<ip/host address>:<port>]
                     | --secure-connection [<ip/host address>:<port>]]
                     [--timeout TIMEOUT]
                     (--swarm | --service SERVICE [SERVICE ...])
  
  Check docker swarm.
  
  optional arguments:
    -h, --help            show this help message and exit
    --connection [/<path to>/docker.socket|<ip/host address>:<port>]
                          Where to find docker daemon socket. (default:
                          /var/run/docker.sock)
    --secure-connection [<ip/host address>:<port>]
                          Where to find TLS protected docker daemon socket.
    --timeout TIMEOUT     Connection timeout in seconds. (default: 10.0)
    --swarm               Check swarm status
    --service SERVICE [SERVICE ...]
                          One or more RegEx that match the names of the
                          services(s) to check.
  usage: check_swarm [-h]
                     [--connection [/<path to>/docker.socket|<ip/host address>:<port>]
                     | --secure-connection [<ip/host address>:<port>]]
                     [--timeout TIMEOUT]
                     (--swarm | --service SERVICE [SERVICE ...])

Gotchas:

-  When using check_docker with older versions of docker (I have seen 1.4 and 1.5) –status only supports ‘running’, ‘restarting’, and ‘paused’.
-  When using check_docker, if no container is specified, all containers are checked. Some containers may return critcal status if the selected check(s) require a running container.

.. |Build Status| image:: https://travis-ci.org/timdaman/check_docker.svg?branch=master
   :target: https://travis-ci.org/timdaman/check_docker
.. |Build Status2| image:: https://travis-ci.org/timdaman/check_docker.svg?branch=master
   :target: https://travis-ci.org/timdaman/check_docker
.. |Code Climate| image:: https://codeclimate.com/github/timdaman/check_docker/badges/gpa.svg
   :target: https://codeclimate.com/github/timdaman/check_docker
.. |Test Coverage| image:: https://codeclimate.com/github/timdaman/check_docker/badges/coverage.svg
   :target: https://codeclimate.com/github/timdaman/check_docker/coverage
