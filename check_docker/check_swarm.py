#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import socket
import stat
from functools import lru_cache
from http.client import HTTPConnection
from sys import argv
from urllib.request import AbstractHTTPHandler, HTTPHandler, HTTPSHandler, OpenerDirector

logger = logging.getLogger()
__author__ = 'Tim Laurence'
__copyright__ = "Copyright 2018"
__credits__ = ['Tim Laurence']
__license__ = "GPL"
__version__ = "2.0.7"

'''
nrpe compatible check for docker swarm

Requires Python 3

Note: I really would have preferred to have used requests for all the network connections but that would have added a
dependency.
'''

DEFAULT_SOCKET = '/var/run/docker.sock'
DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 2375
DEFAULT_HEADERS = [('Accept', 'application/vnd.docker.distribution.manifest.v2+json')]
OK_RC = 0
WARNING_RC = 1
CRITICAL_RC = 2
UNKNOWN_RC = 3

HTTP_GOOD_CODES = range(200, 299)

# These hold the final results
rc = -1
messages = []


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


# Util functions
#############################################################################################


@lru_cache()
def get_url(url):
    response = better_urllib_get.open(url, timeout=timeout)
    return process_urllib_response(response), response.status


def process_urllib_response(response):
    response_bytes = response.read()
    body = response_bytes.decode('utf-8')
    logger.debug(body)
    return json.loads(body)


def get_swarm_status():
    content, status = get_url(daemon + '/swarm')
    return status


def get_service_info(name):
    return get_url(daemon + '/services/{service}'.format(service=name))


def get_services(names):
    services_list, status = get_url(daemon + '/services')
    if status == 406:
        critical("Error checking service status, node is not in swarm mode")
        return []
    elif status not in HTTP_GOOD_CODES:
        unknown("Could not retrieve service info")
        return []

    all_services_names = set(x['Spec']['Name'] for x in services_list)
    if 'all' in names:
        return all_services_names

    filtered = set()
    for matcher in names:
        found = False
        for candidate in all_services_names:
            if re.match("^{}$".format(matcher), candidate):
                filtered.add(candidate)
                found = True
        # If we don't find a service that matches out regex
        if not found:
            critical("No services match {}".format(matcher))

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
def check_swarm():
    status = get_swarm_status()
    process_url_status(status, ok_msg='Node is in a swarm',
                       critical_msg='Node is not in a swarm', unknown_msg='Error accessing swarm info')


def check_service(name):
    info, status = get_service_info(name)
    process_url_status(status, ok_msg='Service {service} is up and running'.format(service=name),
                       critical_msg='Service {service} was not found on the swarm'.format(service=name))


def process_url_status(status, ok_msg=None, critical_msg=None, unknown_msg=None):
    if status in HTTP_GOOD_CODES:
        return ok(ok_msg)
    elif status in [503, 404, 406]:
        return critical(critical_msg)
    else:
        return unknown(unknown_msg)


def process_args(args):
    parser = argparse.ArgumentParser(description='Check docker swarm.')

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

    swarm_group = parser.add_mutually_exclusive_group(required=True)

    # Swarm
    swarm_group.add_argument('--swarm',
                             dest='swarm',
                             default=None,
                             action='store_true',
                             help='Check swarm status')

    # Service
    swarm_group.add_argument('--service',
                             dest='service',
                             action='store',
                             type=str,
                             nargs='+',
                             default=[],
                             help='One or more RegEx that match the names of the services(s) to check.')

    parser.add_argument('-V', action='version', version='%(prog)s {}'.format(__version__))

    if len(args) == 0:
        parser.print_help()

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


def socketfile_permissions_failure(parsed_args):
    if connection_type == 'socket':
        return not (os.path.exists(parsed_args.connection)
                    and stat.S_ISSOCK(os.stat(parsed_args.connection).st_mode)
                    and os.access(parsed_args.connection, os.R_OK)
                    and os.access(parsed_args.connection, os.W_OK))
    else:
        return False


def print_results():
    print('; '.join(messages))


def perform_checks(raw_args):
    args = process_args(raw_args)
    if socketfile_permissions_failure(args):
        unknown("Cannot access docker socket file. User ID={}, socket file={}".format(os.getuid(), args.connection))
    else:
        # Here is where all the work happens
        #############################################################################################
        try:
            if args.swarm:
                check_swarm()
            elif args.service:
                services = get_services(args.service)

                if len(services) > 0:  # Status is set to critical by get_services() if nothing is found for a name
                    for service in services:
                        check_service(service)

        except Exception as e:
            unknown("Exception raised during check: {}".format(repr(e)))

    print_results()


def main():
    perform_checks(argv[1:])
    exit(rc)


if __name__ == '__main__':
    main()
