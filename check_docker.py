#!/usr/bin/env python3
import os
import stat
from collections import deque
from datetime import datetime, timezone
import logging
from sys import argv
from http.client import HTTPConnection
from urllib.request import AbstractHTTPHandler, HTTPHandler, HTTPSHandler, OpenerDirector
import argparse
import json
import socket
from functools import lru_cache
import re

logger = logging.getLogger()
__author__ = 'Tim Laurence'
__copyright__ = "Copyright 2016"
__credits__ = ['Tim Laurence']
__license__ = "GPL"
__version__ = "1.0"

'''
nrpe compatible check for docker containers.

Requires Python 3

Note: I really would have preferred to have used requests for all the network connections but that would have added a
dependency.
'''



DEFAULT_SOCKET = '/var/run/docker.sock'
DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 2375
DEFAULT_MEMORY_UNITS = 'b'
DEFAULT_HEADERS = [('Accept', 'application/vnd.docker.distribution.manifest.v2+json')]
DEFAULT_PUBLIC_REGISTRY = 'https://index.docker.io'
DEFAULT_PUBLIC_AUTH = 'https://auth.docker.io'
UNIT_ADJUSTMENTS = {
    '%': 1,
    'b': 1,
    'k': 1024,
    'm': 1024 * 1024,
    'g': 1024 * 1024 * 1024
}
OK_RC = 0
WARNING_RC = 1
CRITICAL_RC = 2
UNKNOWN_RC = 3

# These hold the final results
rc = -1
messages = []
performance_data = []


# Hacked up urllib to handle sockets
#############################################################################################
# Docker runs a http connection over a socket. http.client is knows how to deal with these
# but lacks some niceties. Urllib wraps that and makes up for some of the deficiencies but
# cannot fix the fact http.client can't read from socket files. In order to take advantage of
# urllib and http.client's  capabilities the class below tweaks HttpConnection and passes it
# to urllib registering for socket:// connections


class SocketFileHandler(AbstractHTTPHandler):
    class SocketFileToHttpConnectionAdaptor(HTTPConnection):
        def __init__(self, socket_file, timeout=DEFAULT_TIMEOUT):
            super().__init__(host='', port=0, timeout=timeout)
            self.socket_file = socket_file

        def connect(self):
            self.sock = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM, proto=0, fileno=None)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.socket_file)

    def socket_open(self, req):
        socket_file, path = req.selector.split(':', 1)
        req.host = socket_file
        req.selector = path
        return self.do_open(self.SocketFileToHttpConnectionAdaptor, req)


better_urllib_get = OpenerDirector()
better_urllib_get.addheaders = DEFAULT_HEADERS.copy()
better_urllib_get.add_handler(HTTPHandler())
better_urllib_get.add_handler(HTTPSHandler())
better_urllib_get.add_handler(SocketFileHandler())

better_urllib_head = OpenerDirector()
better_urllib_head.method = 'HEAD'
better_urllib_head.addheaders = DEFAULT_HEADERS.copy()
better_urllib_head.add_handler(HTTPHandler())
better_urllib_head.add_handler(HTTPSHandler())
better_urllib_head.add_handler(SocketFileHandler())


# Util functions
#############################################################################################
def parse_thresholds(spec, include_units=True, units_required=True):
    """
    Given a spec string break it up into ':' separated chunks. Convert strings to ints as it makes sense

    :param spec:
    :return: A list containing the thresholds in order of warn, crit, and units(if included and present)
    """
    returned = []
    parts = deque(spec.split(':'))
    if not all(parts):
        raise ValueError("Blanks are not allowed in a threshold specification: {}".format(spec))
    # Warn
    returned.append(int(parts.popleft()))
    # Crit
    returned.append(int(parts.popleft()))
    if include_units:
        if len(parts):
            # units
            returned.append(parts.popleft())
        elif units_required:
            raise ValueError("Missing units in {}".format(spec))
        else:
            # units
            returned.append(None)

    if len(parts) != 0:
        raise ValueError("Too many threshold specifiers in {}".format(spec))

    return returned


def evaluate_numeric_thresholds(container, value, warn, crit, name, short_name, min=None, max=None, units='',
                                greater_than=True):
    perf_string = "{}_{}={}{};{};{}".format(container, short_name, value, units, warn, crit)
    if min is not None:
        perf_string += ';{}'.format(min)
        if max is not None:
            perf_string += ';{}'.format(max)
    performance_data.append(perf_string)

    if greater_than:
        if value >= crit:
            critical("{} {} is {}{}".format(container, name, value, units))
        elif value >= warn:
            warning("{} {} is {}{}".format(container, name, value, units))
        else:
            ok("{} {} is {}{}".format(container, name, value, units))
    else:
        if value <= crit:
            critical("{} {} is {}{}".format(container, name, value, units))
        elif value <= warn:
            warning("{} {} is {}{}".format(container, name, value, units))
        else:
            ok("{} {} is {}{}".format(container, name, value, units))


@lru_cache()
def get_url(url):
    response = better_urllib_get.open(url, timeout=timeout)
    return process_urllib_response(response)


@lru_cache()
def head_url(url, auth_token=None):
    if auth_token:
        better_urllib_head.addheaders.append(('Authorization', 'Bearer ' + auth_token))
    response = better_urllib_head.open(url, timeout=timeout)
    if auth_token:
        better_urllib_head.addheaders.pop()
    return response


def process_urllib_response(response):
    bytes = response.read()
    body = bytes.decode('utf-8')
    logger.debug(body)
    return json.loads(body)


def get_container_info(name, type='json'):
    return get_url(daemon + '/containers/{container}/{type}'.format(container=name, type=type))


def get_image_info(name, type='json'):
    return get_url(daemon + '/images/{image}/{type}'.format(image=name, type=type))


@lru_cache()
def get_manifest_auth_token(image_name, auth_source, registry='registry.docker.io', action='pull'):
    url = "{auth_source}/token?service={registry}&scope=repository:{image_name}:{action}".format(
        auth_source=auth_source, registry=registry, image_name=image_name, action=action)
    logger.debug(url)
    response = get_url(url)
    return response['token']


def get_status(container):
    return get_container_info(container)['State']['Status']


def get_containers(names):
    containers_list = get_url(daemon + '/containers/json?all=1')
    all = [x['Names'][0][1:] for x in containers_list]
    if 'all' in names:
        return all
    else:
        filtered = []
        for found in all:
            for matcher in names:
                if re.match("^{}$".format(matcher), found):
                    filtered.append(found)
        return filtered


def set_rc(new_rc):
    global rc
    rc = new_rc if new_rc > rc else rc


def ok(message):
    set_rc(OK_RC)
    messages.append('OK: ' + message)


def warning(message):
    set_rc(WARNING_RC)
    messages.append('WARNING: ' + message)


def critical(message):
    set_rc(CRITICAL_RC)
    messages.append('CRITICAL: ' + message)


def unknown(message):
    set_rc(UNKNOWN_RC)
    messages.append('UNKNOWN: ' + message)


# Checks
#############################################################################################
def check_memory(container, warn, crit, units):
    assert units in UNIT_ADJUSTMENTS, "Invalid memory units"

    status = get_status(container)

    # We can't get stats on container that are not running, the socket read will hang
    if status == 'running':
        inspection = get_container_info(container, 'stats?stream=0')

        if units == '%':
            max = 100
            usage = int(100 * inspection['memory_stats']['usage'] / inspection['memory_stats']['limit'])
        else:
            max = inspection['memory_stats']['limit'] / UNIT_ADJUSTMENTS[units]
            usage = inspection['memory_stats']['usage'] / UNIT_ADJUSTMENTS[units]

        evaluate_numeric_thresholds(container=container, value=usage, warn=warn, crit=crit, units=units, name='memory',
                                    short_name='mem', min=0, max=max)


def check_status(container, desired_state):
    if desired_state.lower() != get_status(container):
        critical("{} state is not {}".format(container, desired_state))
    else:
        ok("{} status is {}".format(container, desired_state))


def check_uptime(container_name, warn, crit, units=None):
    inspection = get_container_info(container_name)['State']['StartedAt']
    only_secs = inspection.split('.')[0]
    start = datetime.strptime(only_secs, "%Y-%m-%dT%H:%M:%S")
    start = start.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    uptime = (now - start).seconds

    graph_padding = 2
    evaluate_numeric_thresholds(container=container_name, value=uptime, units='s', warn=warn, crit=crit,
                                name='uptime',
                                short_name='up', min=0, max=graph_padding, greater_than=False)


def check_restarts(container, warn, crit, units=None):
    inspection = get_container_info(container)

    restarts = int(inspection['RestartCount'])
    graph_padding = 2
    evaluate_numeric_thresholds(container=container, value=restarts, warn=warn, crit=crit, name='restarts',
                                short_name='re', min=0, max=graph_padding)


def check_version(container):
    # find registry and tag
    inspection = get_container_info(container)
    image_id = inspection['Image']
    image_inspection = get_image_info(image_id)
    image_tag = image_inspection['RepoTags'][0]
    try:
        image_digest = image_inspection['RepoDigests'][0].split('@')[1]
    except IndexError:
        unknown('Checksum missing for "{}", try doing a pull'.format(container))
        return

    registry = DEFAULT_PUBLIC_REGISTRY
    full_image_tag = 'library/' + image_tag

    image_name, image_version = full_image_tag.split(':')

    token = get_manifest_auth_token(image_name, DEFAULT_PUBLIC_AUTH)

    # query registry
    url = '{registry}/v2/{image_name}/manifests/{image_version}'.format(registry=registry, image_name=image_name,
                                                                        image_version=image_version)
    reg_info = head_url(url=url, auth_token=token)

    registry_hash = reg_info.getheader('Docker-Content-Digest', None)
    if registry_hash is None:
        raise IndexError('Docker-Content-Digest header missing, cannot check version')
    if registry_hash != image_digest:
        critical("{} is out of date".format(container))


def process_args(args):
    parser = argparse.ArgumentParser(description='Check docker containers.')

    # Connect to local socket or ip address
    connection_group = parser.add_mutually_exclusive_group()
    connection_group.add_argument('--connection',
                                  dest='connection',
                                  action='store',
                                  default=DEFAULT_SOCKET,
                                  type=str,
                                  metavar='[/<path to>/docker.socket|<ip/host address>:<port>]',
                                  help='Where to find docker daemon socket. (default: %(default)s)')

    connection_group.add_argument('--secure-connection',
                                  dest='secure_connection',
                                  action='store',
                                  type=str,
                                  metavar='[<ip/host address>:<port>]',
                                  help='Where to find TLS protected docker daemon socket.')

    # Connection timeout
    parser.add_argument('--timeout',
                        dest='timeout',
                        action='store',
                        type=float,
                        default=DEFAULT_TIMEOUT,
                        help='Connection timeout in seconds. (default: %(default)s)')

    # Container name
    parser.add_argument('--containers',
                        dest='containers',
                        action='store',
                        nargs='+',
                        type=str,
                        default=['all'],
                        help='One or more RegEx that match the names of the container(s) to check. If omitted all containers are checked. (default: %(default)s)')

    # Memory
    parser.add_argument('--memory',
                        dest='memory',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT:UNITS',
                        help='Check memory usage. Valid values for units are %%,b,k,m,g.')

    # State
    parser.add_argument('--status',
                        dest='status',
                        action='store',
                        type=str,
                        help='Desired container status (running, exited, etc). (default: %(default)s)')

    # Age
    parser.add_argument('--uptime',
                        dest='uptime',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT',
                        help='Minimum container uptime in seconds. Use when infrequent crashes are tolerated.')

    # Version
    parser.add_argument('--version',
                        dest='version',
                        default=None,
                        action='store_true',
                        help='Check if the running images are the same version as those in the registry. Useful for finding stale images. Only works with public registry.')

    # Restart
    parser.add_argument('--restarts',
                        dest='restarts',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT',
                        help='Container restart thresholds.')

    parsed_args = parser.parse_args(args=args)

    global timeout
    timeout = parsed_args.timeout

    global daemon
    global connection_type
    if parsed_args.secure_connection:
        daemon = 'https://' + parsed_args.secure_connection
        connection_type = 'https'
    elif parsed_args.connection:
        if parsed_args.connection[0] == '/':
            daemon = 'socket://' + parsed_args.connection + ':'
            connection_type = 'socket'
        else:
            daemon = 'http://' + parsed_args.connection
            connection_type = 'http'

    return parsed_args


def no_checks_present(parsed_args):
    # Look for all functions whose name starts with 'check_'
    checks = [key[6:] for key in globals().keys() if key.startswith('check_')]
    return all(getattr(parsed_args, check) is None for check in checks)


def socketfile_permissions_failure(parsed_args):
    if connection_type == 'socket':
        return not (os.path.exists(parsed_args.connection)
                    and stat.S_ISSOCK(os.stat(parsed_args.connection).st_mode)
                    and os.access(parsed_args.connection, os.R_OK)
                    and os.access(parsed_args.connection, os.W_OK))
    else:
        return False


def print_results():
    messages_concat = '; '.join(messages)
    perfdata_concat = ' '.join(performance_data)
    if len(performance_data) > 0:
        print(messages_concat + '|' + perfdata_concat)
    else:
        print(messages_concat)


if __name__ == '__main__':

    #############################################################################################
    args = process_args(argv[1:])

    if socketfile_permissions_failure(args):
        unknown("Cannot access docker socket file. User ID={}, socket file={}".format(os.getuid(), args.connection))
    elif no_checks_present(args):
        unknown("No checks specified.")
    else:
        # Here is where all the work happens
        #############################################################################################
        try:
            containers = get_containers(args.containers)

            if len(containers) == 0:
                unknown("No containers names found matching criteria")
            else:
                for container in containers:

                    # Check status
                    if args.status:
                        check_status(container, args.status)

                    # Check memory usage
                    if args.memory:
                        check_memory(container, *parse_thresholds(args.memory, units_required=False))

                    # Check uptime
                    if args.uptime:
                        check_uptime(container, *parse_thresholds(args.uptime, include_units=False))

                    # Check version
                    if args.version:
                        check_version(container)

                    # Check restart count
                    if args.restarts:
                        check_restarts(container, *parse_thresholds(args.restarts, include_units=False))

        except Exception as e:
            unknown("Exception raised during check: {}".format(repr(e)))

    print_results()
    exit(rc)
