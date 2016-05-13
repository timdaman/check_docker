#!/usr/bin/env python3
from copy import copy
from http.client import HTTPConnection
from urllib.request import AbstractHTTPHandler, HTTPHandler, HTTPSHandler, OpenerDirector

__author__ = 'Tim Laurence'
import argparse
import json
import socket
from functools import lru_cache


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
# FYI, this hostname is simply a CNAME to registry-origin.docker.io but  were sticking with the docker client
# behavior rather than skip a DNS lookup for compatibility
DEFAULT_PUBLIC_REGISTRY = 'https://registry-1.docker.io'
UNIT_ADJUSTMENTS = {
    '%': 1,
    'b': 1,
    'k': 1024,
    'm': 1024 * 1024,
    'g': 1024 * 1024 * 1024
}
DEFAULT_HEADERS=(('Accept', 'application/vnd.docker.distribution.manifest.v2+json'))

rc = 0
messages = []
performance_data = []
containers = []
timeout = DEFAULT_TIMEOUT


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
            print("Socket read ")
            self.sock = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM, proto=0, fileno=None)
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.socket_file)

    def socket_open(self, req):
        socket_file, path = req.selector.split(':')
        req.host = socket_file
        req.selector = path
        return self.do_open(self.SocketFileToHttpConnectionAdaptor, req)


sock = OpenerDirector()
sock.add_handler(HTTPHandler())
sock.add_handler(HTTPSHandler())
sock.add_handler(SocketFileHandler())

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


def evaluate_numeric_thresholds(container, value, warn, crit, name, units='', less_than=False):

    if less_than:
        if value <= crit:
            critical("{} {} is {}{}".format(container, name, value, units))
        elif value <= warn:
            warning("{} {} is {}{}".format(container, name, value, units))
    else:
        if value >= crit:
            critical("{} {} is {}{}".format(container, name, value, units))
        elif value >= warn:
            warning("{} {} is {}{}".format(container, name, value, units))
    ok("{} {} is {}{}".format(container, name, value, units))

@lru_cache()
def get_url(url, get_auth=True):
    print(url)
    headers = [DEFAULT_HEADERS]
    if get_auth:
        headers = add_auth_header(url, headers)
    sock.addheaders = headers
    response = sock.open(url, timeout=timeout)
    bytes = response.read()
    body = bytes.decode('utf-8')
    # TODO: Throw error when body.startswith('No such container: ')
    return json.loads(body)

@lru_cache()
def head_url(url, get_auth=True):
    headers = [DEFAULT_HEADERS]
    if get_auth:
        headers = add_auth_header(url, headers)
    sock.addheaders = headers
    sock.method = 'HEAD'
    response = sock.open(url, timeout=timeout)
    sock.method = None
    return dict(response.getheaders())

def add_auth_header(url, headers):
    head_resp = head_url(url, get_auth=False)
    if 'Www-Authenticate' in head_resp:
        auth_resp = head_resp['Www-Authenticate']
        auth_parts = auth_resp.lstrip('Bearer realm=').replace('"', '').split(',')
        auth_url = auth_parts[0] + '?' + '&'.join(auth_parts[1:])
        token = get_url(auth_url)['token']
        headers.append(('Authorization', 'Bearer ' + token))
    return headers


def ok(message):
    rc = 0
    messages.append('OK ' + message)


def warning(message):
    rc = 1
    messages.append('WARNING ' + message)


def critical(message):
    rc = 2
    messages.append('CRITICAL ' + message)


def unknown(message):
    rc = 3
    messages.append('UNKNOWN ' + message)


def get_container_info(name, type='json'):
    return get_url(daemon + '/containers/{container}/{type}'.format(container=name, type=type))

def check_memory(container, warn, crit, units):
    assert units in UNIT_ADJUSTMENTS, "Invalid memory units"

    status = get_container_info(container)['State']['Status']
    # We can't get stats on container that are not running, the socket read will hang
    if status == 'running':
        inspection = get_container_info(container, 'stats?stream=0')
        usage = inspection['memory_stats']['usage'] / UNIT_ADJUSTMENTS[units]

        if units == '%':
            usage = int(100 * usage / inspection['memory_stats']['limit'])

        performance_data.append("{}_mem={}".format(container, usage))
        evaluate_numeric_thresholds(container=container, value=usage, warn=warn, crit=crit, units=units, name='memory')


def check_status(container, desired_state):
    inspection = get_container_info(container)
    if desired_state.lower() != inspection['State']['Status']:
        critical("{} state is not {}".format(container, desired_state))
    else:
        ok("{} state is {}".format(container, desired_state))


def check_restarts(container, warn, crit, units):
    inspection = get_container_info(container)

    restarts = int(inspection['RestartCount'])
    evaluate_numeric_thresholds(container=container, value=restarts, warn=warn, crit=crit, name='restarts')


def check_image_version(container):
    # find registry and tag
    inspection = get_container_info(container)
    image = inspection['Config']['Image']
    local_hash = inspection['Image']
    if image.find('/') >= 0:  # Private registry
        registry, image_name = image.split('/')
        # TODO: Handle secure local registries
        registry = 'http://' + registry
    else:  # Default public registry
        registry = DEFAULT_PUBLIC_REGISTRY
        image_name = 'library/' + image

    if image_name.find(':') >= 0:
        image_name, image_tag = image_name.split(':')
    else:
        image_tag = "latest"

    # query registry
    url = registry + '/v2/{image}/manifests/{tag}'.format(image=image_name, tag=image_tag)
    reg_info = get_url(
        '{registry}/v2/{image}/manifests/{tag}'.format(registry=registry, image=image_name, tag=image_tag))

    registry_hash = reg_info['Docker-Content-Digest']

    if registry_hash != local_hash:
        critical("{} is out of date".format(container))


parser = argparse.ArgumentParser(description='Check docker images.')

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
                    nargs='*',
                    type=str,
                    default='all',
                    help='Name of container(s) to check. If omitted all containers are checked. (default: %(default)s)')

# Memory
parser.add_argument('--memory',
                    dest='memory',
                    action='store',
                    type=str,
                    metavar='[WARN:CRIT:UNITS]',
                    help='Check memory usage. Valid values for units are %%,b,k,m,g for percent of memory limit, bytes, kilobytes, megabytes, gigabytes.')

# State
parser.add_argument('--status',
                    dest='status',
                    action='store',
                    type=str,
                    help='Desired container status (running, exited, etc). (default: %(default)s)')

# Restart
parser.add_argument('--restart',
                    dest='restart',
                    action='store',
                    nargs='?',
                    type=str,
                    metavar='WARN:CRIT',
                    help='Container restart thresholds.')

# image version
parser.add_argument('--image-version',
                    dest='image',
                    action='store_true',
                    # type=str,
                    # nargs='?',
                    # default='secure',
                    # choices=['secure', 'insecure'],
                    help="Check if the running image is the current release. Specify 'insecure' if registry doesn't support TLS. (default: %(default)s)")

args = parser.parse_args()

timeout = args.timeout

if args.secure_connection:
    daemon = 'https://' + args.secure_connection
elif args.connection:
    if args.connection[0] == '/':
        daemon = 'socket://' + args.connection + ':'
    else:
        daemon = 'http://' + args.connection
else:
    raise ValueError('connection xor secure_connection must be set')

if args.containers == 'all':
    containers = [x['Names'][0][1:] for x in get_url(daemon + '/containers/json?all=1')]
else:
    containers = args.containers

for container in containers:
    # Check status
    if args.status:
        check_status(container, args.status)

    # Check memory usage
    if args.memory:
        check_memory(container, *parse_thresholds(args.memory))

    # Check restart count
    if args.restart:
        check_restarts(container, *parse_thresholds(args.restart))

    # Check for image updates
    if args.image:
        check_image_version(container)

print(messages)
exit(rc)
