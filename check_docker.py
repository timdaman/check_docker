#!/usr/bin/env python3
from datetime import datetime, timezone

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

from sys import argv
from http.client import HTTPConnection
from urllib.request import AbstractHTTPHandler, HTTPHandler, HTTPSHandler, OpenerDirector
import argparse
import json
import socket
from functools import lru_cache
import re


DEFAULT_SOCKET = '/var/run/docker.sock'
DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 2375
DEFAULT_MEMORY_UNITS = 'b'
DEFAULT_HEADERS = (('Accept', 'application/vnd.docker.distribution.manifest.v2+json'))
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
        socket_file, path = req.selector.split(':')
        req.host = socket_file
        req.selector = path
        return self.do_open(self.SocketFileToHttpConnectionAdaptor, req)


better_urllib = OpenerDirector()
better_urllib.addheaders = [DEFAULT_HEADERS]
better_urllib.add_handler(HTTPHandler())
better_urllib.add_handler(HTTPSHandler())
better_urllib.add_handler(SocketFileHandler())

# Util functions
#############################################################################################
def parse_thresholds(spec):
    """
    Given a spec string break it up into ':' separated chunks. Convert strings to ints as it makes sense

    :param spec:
    :return: The thresholds, as intergers
    """
    parts = spec.split(':')
    warn = int(parts[0])
    crit = int(parts[1])
    units = parts[2] if len(parts) >= 3 else None
    return warn, crit, units


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
    response = better_urllib.open(url, timeout=timeout)
    bytes = response.read()
    body = bytes.decode('utf-8')
    return json.loads(body)


def get_container_info(name, type='json'):
    return get_url(daemon + '/containers/{container}/{type}'.format(container=name, type=type))


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


def check_uptime(container, warn, crit, units=None):
    inspection = get_container_info(container)['State']['StartedAt']
    only_secs = inspection.split('.')[0]
    start = datetime.strptime(only_secs, "%Y-%m-%dT%H:%M:%S")
    start = start.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    uptime = (now - start).seconds

    graph_padding = 2
    evaluate_numeric_thresholds(container=container, value=uptime, units='s', warn=warn, crit=crit,
                                name='uptime',
                                short_name='up', min=0, max=graph_padding, greater_than=False)


def check_restarts(container, warn, crit, units=None):
    inspection = get_container_info(container)

    restarts = int(inspection['RestartCount'])
    graph_padding = 2
    evaluate_numeric_thresholds(container=container, value=restarts, warn=warn, crit=crit, name='restarts',
                                short_name='re', min=0, max=graph_padding)


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
                        metavar='[WARN:CRIT:UNITS]',
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
                        help='Minimum container uptime in seconds. Used to rapid restarting. Should be less than you monitoring poll interval.')

    # Restart
    parser.add_argument('--restarts',
                        dest='restarts',
                        action='store',
                        nargs='?',
                        type=str,
                        metavar='WARN:CRIT',
                        help='Container restart thresholds.')

    parsed_args = parser.parse_args(args=args)

    global timeout
    timeout = parsed_args.timeout

    global daemon
    if parsed_args.secure_connection:
        daemon = 'https://' + parsed_args.secure_connection
    elif parsed_args.connection:
        if parsed_args.connection[0] == '/':
            daemon = 'socket://' + parsed_args.connection + ':'
        else:
            daemon = 'http://' + parsed_args.connection

    return parsed_args


def no_checks_present(parsed_args):
    # Look for all functions whose name starts with 'check_'
    checks = [key[6:] for key in globals().keys() if key.startswith('check_')]
    return all(getattr(parsed_args, check) is None for check in checks)


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

    if no_checks_present(args):
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
                        check_memory(container, *parse_thresholds(args.memory))

                    # Check uptime
                    if args.uptime:
                        check_uptime(container, *parse_thresholds(args.uptime))

                    # Check restart count
                    if args.restarts:
                        check_restarts(container, *parse_thresholds(args.restarts))

        except Exception as e:
            unknown("Exception raised during check: {}".format(str(e)))

    print_results()
    exit(rc)
