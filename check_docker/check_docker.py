#!/usr/bin/env python3
import argparse
import json
import logging
# logging.basicConfig(level=logging.DEBUG)
import math
import os
import re
import socket
import stat
import traceback
from collections import deque, namedtuple, UserDict, defaultdict
from concurrent import futures
from datetime import datetime, timezone
from functools import lru_cache
from http.client import HTTPConnection
from sys import argv
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.request import AbstractHTTPHandler, HTTPHandler, HTTPSHandler, OpenerDirector, HTTPRedirectHandler, \
    Request, HTTPBasicAuthHandler

logger = logging.getLogger()
__author__ = 'Tim Laurence'
__copyright__ = "Copyright 2018"
__credits__ = ['Tim Laurence']
__license__ = "GPL"
__version__ = "2.0.7"

'''
nrpe compatible check for docker containers.

Requires Python 3

Note: I really would have preferred to have used requests for all the network connections but that would have added a
dependency.
'''

DEFAULT_SOCKET = '/var/run/docker.sock'
DEFAULT_TIMEOUT = 10.0
DEFAULT_PORT = 2375
DEFAULT_MEMORY_UNITS = 'B'
DEFAULT_HEADERS = [('Accept', 'application/vnd.docker.distribution.manifest.v2+json')]
DEFAULT_PUBLIC_REGISTRY = 'registry-1.docker.io'

# The second value is the power to raise the base to.
UNIT_ADJUSTMENTS_TEMPLATE = {
    '%': 0,
    'B': 0,
    'KB': 1,
    'MB': 2,
    'GB': 3,
    'TB': 4
}
unit_adjustments = None

OK_RC = 0
WARNING_RC = 1
CRITICAL_RC = 2
UNKNOWN_RC = 3

# These hold the final results
rc = -1
messages = []
performance_data = []

ImageName = namedtuple('ImageName', "registry name tag full_name")


class ThresholdSpec(UserDict):
    def __init__(self, warn, crit, units=''):
        super().__init__(warn=warn, crit=crit, units=units)

    def __getattr__(self, item):
        return self[item]


# How much threading can we do? We are generally not CPU bound so I am using this a worse case cap
DEFAULT_PARALLELISM = 10

# Holds list of all threads
threads = []

# This is used during testing
DISABLE_THREADING = False


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


# Tokens are not cached because I expect the callers to cache the responses
class Oauth2TokenAuthHandler(HTTPBasicAuthHandler):
    auth_failure_tracker = defaultdict(int)

    def http_response(self, request, response):
        code, hdrs = response.code, response.headers

        www_authenticate_header = response.headers.get('www-authenticate', None)
        if code == 401 and www_authenticate_header:
            scheme = www_authenticate_header.split()[0]
            if scheme.lower() == 'bearer':
                return self.process_oauth2(request, response, www_authenticate_header)

        return response

    https_response = http_response

    @staticmethod
    def _get_outh2_token(www_authenticate_header):
        auth_fields = dict(re.findall(r"""(?:(?P<key>[^ ,=]+)="([^"]+)")""", www_authenticate_header))

        auth_url = "{realm}?scope={scope}&service={service}".format(
            realm=auth_fields['realm'],
            scope=auth_fields['scope'],
            service=auth_fields['service'],
        )
        token_request = Request(auth_url)
        token_request.add_header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
        token_response = request.urlopen(token_request)
        return process_urllib_response(token_response)['token']

    def process_oauth2(self, request, response, www_authenticate_header):

        # This keep infinite auth loops from happening
        full_url = request.full_url
        self.auth_failure_tracker[full_url] += 1
        if self.auth_failure_tracker[full_url] > 1:
            raise HTTPError(full_url, 401, "Stopping Oauth2 failure loop for {}".format(full_url),
                            response.headers, response)

        auth_token = self._get_outh2_token(www_authenticate_header)

        request.add_unredirected_header('Authorization', 'Bearer ' + auth_token)
        return self.parent.open(request, timeout=request.timeout)


# Got some help from this example https://gist.github.com/FiloSottile/2077115
class HeadRequest(Request):
    def get_method(self):
        return "HEAD"


better_urllib_get = OpenerDirector()
better_urllib_get.addheaders = DEFAULT_HEADERS.copy()
better_urllib_get.add_handler(HTTPHandler())
better_urllib_get.add_handler(HTTPSHandler())
better_urllib_get.add_handler(HTTPRedirectHandler())
better_urllib_get.add_handler(SocketFileHandler())
better_urllib_get.add_handler(Oauth2TokenAuthHandler())


class RegistryError(Exception):
    def __init__(self, response):
        self.response_obj = response


# Util functions
#############################################################################################
def parse_thresholds(spec, include_units=True, units_required=True):
    """
    Given a spec string break it up into ':' separated chunks. Convert strings to ints as it makes sense

    :param spec: The threshold specification being parsed
    :param include_units: Specifies that units should be processed and returned if present
    :param units_required: Mark spec as invalid if the units are missing.
    :return: A list containing the thresholds in order of warn, crit, and units(if included and present)
    """
    parts = deque(spec.split(':'))
    if not all(parts):
        raise ValueError("Blanks are not allowed in a threshold specification: {}".format(spec))

    # Warn
    warn = int(parts.popleft())
    # Crit
    crit = int(parts.popleft())

    units = ''
    if include_units:
        if len(parts):
            # units
            units = parts.popleft()
        elif units_required:
            raise ValueError("Missing units in {}".format(spec))

    if len(parts) != 0:
        raise ValueError("Too many threshold specifiers in {}".format(spec))

    return ThresholdSpec(warn=warn, crit=crit, units=units)


def pretty_time(seconds):
    remainder = seconds
    result = []
    if remainder > 24 * 60 * 60:
        days, remainder = divmod(remainder, 24 * 60 * 60)
        result.append("{}d".format(int(days)))
    if remainder > 60 * 60:
        hours, remainder = divmod(remainder, 60 * 60)
        result.append("{}h".format(int(hours)))
    if remainder > 60:
        minutes, remainder = divmod(remainder, 60)
        result.append("{}min".format(int(minutes)))
    result.append("{}s".format(int(remainder)))
    return result


def evaluate_numeric_thresholds(container, value, thresholds, name, short_name,
                                min=None, max=None, greater_than=True):
    rounder = lambda x: round(x, 2)

    INTEGER_UNITS = ['B', '%', '']

    # Some units don't have decimal places
    rounded_value = int(value) if thresholds.units in INTEGER_UNITS else rounder(value)

    perf_string = "{container}_{short_name}={value}{units};{warn};{crit}".format(
        container=container,
        short_name=short_name,
        value=rounded_value,
        **thresholds)
    if min is not None:
        rounded_min = math.floor(min) if thresholds.units in INTEGER_UNITS else rounder(min)
        perf_string += ';{}'.format(rounded_min)
        if max is not None:
            rounded_max = math.ceil(max) if thresholds.units in INTEGER_UNITS else rounder(max)
            perf_string += ';{}'.format(rounded_max)

    global performance_data
    performance_data.append(perf_string)

    if thresholds.units == 's':
        nice_time = ' '.join(pretty_time(rounded_value)[:2])
        results_str = "{} {} is {}".format(container, name, nice_time)
    else:
        results_str = "{} {} is {}{}".format(container, name, rounded_value, thresholds.units)

    if greater_than:
        comparator = lambda value, threshold: value >= threshold
    else:
        comparator = lambda value, threshold: value <= threshold

    if comparator(value, thresholds.crit):
        critical(results_str)
    elif comparator(value, thresholds.warn):
        warning(results_str)
    else:
        ok(results_str)


@lru_cache(maxsize=None)
def get_url(url):
    logger.debug("get_url: {}".format(url))
    response = better_urllib_get.open(url, timeout=timeout)
    logger.debug("get_url: {} {}".format(url, response.status))
    return process_urllib_response(response), response.status


@lru_cache(maxsize=None)
def head_url(url):
    # Follow redirects
    response = better_urllib_get.open(HeadRequest(url), timeout=timeout)
    logger.debug("{} {}".format(url, response.status))
    return response


def process_urllib_response(response):
    response_bytes = response.read()
    body = response_bytes.decode('utf-8')
    # logger.debug("BODY: {}".format(body))
    return json.loads(body)


def get_container_info(name):
    content, _ = get_url(daemon + '/containers/{container}/json'.format(container=name))
    return content


def get_image_info(name):
    content, _ = get_url(daemon + '/images/{image}/json'.format(image=name))
    return content


def get_state(container):
    return get_container_info(container)['State']


def get_stats(container):
    content, _ = get_url(daemon + '/containers/{container}/stats?stream=0'.format(container=container))
    return content


def get_ps_name(name_list):
    # Pick the name that starts with a '/' but doesn't contain a '/' and return that value
    for name in name_list:
        if '/' not in name[1:] and name[0] == '/':
            return name[1:]
    else:
        raise NameError("Error when trying to identify 'ps' name in {}".format(name_list))


def get_containers(names, require_present):
    containers_list, _ = get_url(daemon + '/containers/json?all=1')

    all_container_names = set(get_ps_name(x['Names']) for x in containers_list)

    if 'all' in names:
        return all_container_names

    filtered = set()
    for matcher in names:
        found = False
        for candidate in all_container_names:
            if re.match("^{}$".format(matcher), candidate):
                filtered.add(candidate)
                found = True
        # If we don't find a container that matches out regex
        if require_present and not found:
            critical("No containers match {}".format(matcher))

    return filtered


def get_container_digest(container):
    # find registry and tag
    inspection = get_container_info(container)
    image_id = inspection['Image']
    image_info = get_image_info(image_id)
    try:
        return image_info['RepoDigests'][0].split('@')[1]
    except IndexError:
        return None


def get_container_image_urls(container):
    inspection = get_container_info(container)
    image_id = inspection['Image']
    image_info = get_image_info(image_id)
    return image_info['RepoTags']


def normalize_image_name_to_manifest_url(image_name, insecure_registries):
    parsed_url = parse_image_name(image_name)

    lower_insecure = [reg.lower() for reg in insecure_registries]

    # Registry query url
    scheme = 'http' if parsed_url.registry.lower() in lower_insecure else 'https'
    url = '{scheme}://{registry}/v2/{image_name}/manifests/{image_tag}'.format(scheme=scheme,
                                                                               registry=parsed_url.registry,
                                                                               image_name=parsed_url.name,
                                                                               image_tag=parsed_url.tag)
    return url, parsed_url.registry


# Auth servers seem picky about being hit too hard. Can't figure out why. ;)
# As result it is best to single thread this check
# This is based on https://docs.docker.com/registry/spec/auth/token/#requesting-a-token
def get_digest_from_registry(url):
    logger.debug("get_digest_from_registry")
    # query registry
    # TODO: Handle logging in if needed
    registry_info = head_url(url=url)

    digest = registry_info.getheader('Docker-Content-Digest', None)
    if digest is None:
        raise RegistryError(response=registry_info)
    return digest


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


def require_running(name):
    def inner_decorator(func):
        def wrapper(container, *args, **kwargs):
            container_state = get_state(container)
            if container_state["Running"]:
                func(container, *args, **kwargs)
            else:
                # container is not running, can't perform check
                critical('{container} is not "running", cannot check {check}"'.format(container=container,
                                                                                      check=name))

        return wrapper

    return inner_decorator


def multithread_execution(disable_threading=DISABLE_THREADING):
    def inner_decorator(func):
        def wrapper(container, *args, **kwargs):
            if DISABLE_THREADING:
                func(container, *args, **kwargs)
            else:
                threads.append(parallel_executor.submit(func, container, *args, **kwargs))

        return wrapper

    return inner_decorator


def singlethread_execution(disable_threading=DISABLE_THREADING):
    def inner_decorator(func):
        def wrapper(container, *args, **kwargs):
            if DISABLE_THREADING:
                func(container, *args, **kwargs)
            else:
                threads.append(serial_executor.submit(func, container, *args, **kwargs))

        return wrapper

    return inner_decorator


def parse_image_name(image_name):
    """
    Parses image names into their constituent parts.
    :param image_name:
    :return: ImageName
    """

    # These are based on information found here
    #   https://docs.docker.com/engine/reference/commandline/tag/#extended-description
    #   https://github.com/docker/distribution/blob/master/reference/regexp.go
    host_segment_re = '[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?'
    hostname_re = r'({host_segment}\.)+{host_segment}'.format(host_segment=host_segment_re)
    registry_re = r'((?P<registry>({hostname_re}(:\d+)?|{host_segment_re}:\d+))/)'.format(
        host_segment_re=host_segment_re, hostname_re=hostname_re)
    name_component_ends_re = '[a-z0-9]'
    name_component_middle_re = '[a-z0-9._-]'  # Ignoring spec limit of two _
    name_component_re = '({end}{middle}*{end}|{end})'.format(end=name_component_ends_re,
                                                             middle=name_component_middle_re)
    image_name_re = "(?P<image_name>({name_component}/)*{name_component})".format(name_component=name_component_re)
    image_tag_re = '(?P<image_tag>[a-zA-Z0-9_][a-zA-Z0-9_.-]*)'
    full_re = '^{registry}?{image_name}(:{image_tag})?$'.format(registry=registry_re, image_name=image_name_re,
                                                                image_tag=image_tag_re)
    parsed = re.match(full_re, image_name)

    registry = parsed.group('registry') if parsed.group('registry') else DEFAULT_PUBLIC_REGISTRY

    image_name = parsed.group('image_name')
    image_name = image_name if '/' in image_name or registry != DEFAULT_PUBLIC_REGISTRY else 'library/' + image_name

    image_tag = parsed.group('image_tag')
    image_tag = image_tag if image_tag else 'latest'

    full_image_name = "{registry}/{image_name}:{image_tag}".format(
        registry=registry,
        image_name=image_name,
        image_tag=image_tag)

    return ImageName(registry=registry, name=image_name, tag=image_tag, full_name=full_image_name)


# Checks
#############################################################################################

@multithread_execution()
@require_running(name='memory')
def check_memory(container, thresholds):
    if not thresholds.units in unit_adjustments:
        unknown("Memory units must be one of  {}".format(list(unit_adjustments.keys())))
        return

    inspection = get_stats(container)

    # Subtracting cache to match what `docker stats` does.
    adjusted_usage = inspection['memory_stats']['usage'] - inspection['memory_stats']['stats']['total_cache']
    if thresholds.units == '%':
        max = 100
        usage = int(100 * adjusted_usage / inspection['memory_stats']['limit'])
    else:
        max = inspection['memory_stats']['limit'] / unit_adjustments[thresholds.units]
        usage = adjusted_usage / unit_adjustments[thresholds.units]

    evaluate_numeric_thresholds(container=container, value=usage, thresholds=thresholds, name='memory',
                                short_name='mem', min=0, max=max)


@multithread_execution()
def check_status(container, desired_state):
    normized_desired_state = desired_state.lower()
    state = get_state(container)
    # On new docker engines the status holds whatever the current state is, running, stopped, paused, etc.
    if "Status" in state:
        if normized_desired_state != get_state(container)['Status']:
            critical("{} state is not {}".format(container, desired_state))
            return
    else:  # Assume we are checking an older docker which only uses keys and true false values to indicate state
        leading_cap_state_name = normized_desired_state.title()
        if leading_cap_state_name in state:
            if not state[leading_cap_state_name]:
                critical("{} state is not {}".format(container, leading_cap_state_name))
                return
        else:
            unknown("For {} cannot find a value for {} in state".format(container, desired_state))
    ok("{} status is {}".format(container, desired_state))


@multithread_execution()
@require_running('health')
def check_health(container):
    state = get_state(container)
    if "Health" in state and "Status" in state["Health"]:
        health = state["Health"]["Status"]
        message = "{} is {}".format(container, health)
        if health == 'healthy':
            ok(message)
        elif health == 'unhealthy':
            critical(message)
        else:
            unknown(message)
    else:
        unknown('{} has no health check data'.format(container))


@multithread_execution()
@require_running('uptime')
def check_uptime(container, thresholds):
    inspection = get_container_info(container)['State']['StartedAt']
    only_secs = inspection[0:19]
    start = datetime.strptime(only_secs, "%Y-%m-%dT%H:%M:%S")
    start = start.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    uptime = (now - start).total_seconds()

    graph_padding = 2
    thresholds.units = 's'
    evaluate_numeric_thresholds(container=container, value=uptime, thresholds=thresholds, name='uptime',
                                short_name='up', min=0, max=graph_padding, greater_than=False)


@multithread_execution()
@require_running('restarts')
def check_restarts(container, thresholds):
    inspection = get_container_info(container)

    restarts = int(inspection['RestartCount'])
    graph_padding = 2
    evaluate_numeric_thresholds(container=container, value=restarts, thresholds=thresholds, name='restarts',
                                short_name='re', min=0, max=graph_padding)


@singlethread_execution()
def check_version(container, insecure_registries):
    image_digest = get_container_digest(container)
    if image_digest is None:
        unknown('Checksum missing for "{}", try doing a pull'.format(container))
        return

    image_urls = get_container_image_urls(container=container)
    if len(image_urls) > 1:
        unknown('"{}" has multiple tags/names. Unsure which one to use to check the version.'.format(container))
        return
    elif len(image_urls) == 0:
        unknown('"{}" has last no repository tag. Is this anywhere else?'.format(container))
        return

    url, registry = normalize_image_name_to_manifest_url(image_urls[0], insecure_registries)

    try:
        registry_hash = get_digest_from_registry(url)
    except URLError as e:
        if hasattr(e.reason, 'reason') and e.reason.reason == 'UNKNOWN_PROTOCOL':
            unknown(
                "TLS error connecting to registry {} for {}, should you use the '--insecure-registry' flag?" \
                    .format(registry, container))
            return
        elif hasattr(e.reason, 'strerror') and e.reason.strerror == 'nodename nor servname provided, or not known':
            unknown(
                "Cannot reach registry for {} at {}".format(container, url))
            return
        else:
            raise e
    except RegistryError as e:
        unknown("Cannot check version, couldn't retrieve digest for {} while checking {}.".format(container, url))
        return

    if registry_hash == image_digest:
        ok("{}'s version matches registry".format(container))
        return
    critical("{}'s version does not match registry".format(container))


def calculate_cpu_capacity_precentage(info, stats):
    host_config = info['HostConfig']

    if 'online_cpus' in stats['cpu_stats']:
        num_cpus = stats['cpu_stats']['online_cpus']
    else:
        num_cpus = len(stats['cpu_stats']['cpu_usage']['percpu_usage'])

    # Identify limit system being used
    # --cpus
    if 'NanoCpus' in host_config and host_config['NanoCpus'] != 0:
        period = 1000000000
        quota = host_config['NanoCpus']
    # --cpu-quota
    elif 'CpuQuota' in host_config and host_config['CpuQuota'] != 0:
        period = 100000 if host_config['CpuPeriod'] == 0 else host_config['CpuPeriod']
        quota = host_config['CpuQuota']
    # unlimited
    else:
        period = 1
        quota = num_cpus

    if period * num_cpus < quota:
        # This handles the case where the quota is actually bigger than amount available by all the cpus.
        available_limit_ratio = 1
    else:
        available_limit_ratio = (period * num_cpus) / quota

    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
    system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
    usage = (cpu_delta / system_delta) * available_limit_ratio
    usage = round(usage * 100, 0)
    return usage


@multithread_execution()
@require_running('cpu')
def check_cpu(container, thresholds):
    info = get_container_info(container)

    stats = get_stats(container=container)

    usage = calculate_cpu_capacity_precentage(info=info, stats=stats)

    max = 100
    thresholds.units = '%'
    evaluate_numeric_thresholds(container=container, value=usage, thresholds=thresholds, name='cpu', short_name='cpu',
                                min=0, max=max)


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

    base_group = parser.add_mutually_exclusive_group()
    base_group.add_argument('--binary_units',
                            dest='units_base',
                            action='store_const',
                            const=1024,
                            help='Use a base of 1024 when doing calculations of KB, MB, GB, & TB (This is default)')

    base_group.add_argument('--decimal_units',
                            dest='units_base',
                            action='store_const',
                            const=1000,
                            help='Use a base of 1000 when doing calculations of KB, MB, GB, & TB')
    parser.set_defaults(units_base=1024)

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

    # Container name
    parser.add_argument('--present',
                        dest='present',
                        default=False,
                        action='store_true',
                        help='Modifies --containers so that each RegEx must match at least one container.')

    # Threads
    parser.add_argument('--threads',
                        dest='threads',
                        default=DEFAULT_PARALLELISM,
                        action='store',
                        type=int,
                        help='This + 1 is the maximum number of concurent threads/network connections. (default: %(default)s)')

    # CPU
    parser.add_argument('--cpu',
                        dest='cpu',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT',
                        help='Check cpu usage percentage taking into account any limits. Valid values are 0 - 100.')

    # Memory
    parser.add_argument('--memory',
                        dest='memory',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT:UNITS',
                        help='Check memory usage taking into account any limits. Valid values for units are %%,B,KB,MB,GB.')

    # State
    parser.add_argument('--status',
                        dest='status',
                        action='store',
                        type=str,
                        help='Desired container status (running, exited, etc).')

    # Health
    parser.add_argument('--health',
                        dest='health',
                        default=None,
                        action='store_true',
                        help="Check container's health check status")

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
                        help='Check if the running images are the same version as those in the registry. Useful for finding stale images. Does not support login.')

    # Version
    parser.add_argument('--insecure-registries',
                        dest='insecure_registries',
                        action='store',
                        nargs='+',
                        type=str,
                        default=[],
                        help='List of registries to connect to with http(no TLS). Useful when using "--version" with images from insecure registries.')

    # Restart
    parser.add_argument('--restarts',
                        dest='restarts',
                        action='store',
                        type=str,
                        metavar='WARN:CRIT',
                        help='Container restart thresholds.')

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


def no_checks_present(parsed_args):
    # Look for all functions whose name starts with 'check_'
    checks = [key[6:] for key in globals().keys() if key.startswith('check_')]
    # Act like --present is a check though it is not implemented like one
    return all(getattr(parsed_args, check) is None for check in checks) and not parsed_args.present


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


def perform_checks(raw_args):
    args = process_args(raw_args)

    global parallel_executor
    parallel_executor = futures.ThreadPoolExecutor(max_workers=args.threads)
    global serial_executor
    serial_executor = futures.ThreadPoolExecutor(max_workers=1)

    global unit_adjustments
    unit_adjustments = {key: args.units_base ** value for key, value in UNIT_ADJUSTMENTS_TEMPLATE.items()}

    if socketfile_permissions_failure(args):
        unknown("Cannot access docker socket file. User ID={}, socket file={}".format(os.getuid(), args.connection))
        return

    if args.containers == ["all"] and args.present:
        unknown("You can not use --present without --containers")
        return

    if no_checks_present(args):
        unknown("No checks specified.")
        return

    # Here is where all the work happens
    #############################################################################################
    containers = get_containers(args.containers, args.present)

    if len(containers) == 0 and not args.present:
        unknown("No containers names found matching criteria")
        return

    for container in containers:

        # Check status
        if args.status:
            check_status(container, args.status)

        # Check version
        if args.version:
            check_version(container, args.insecure_registries)

        # below are checks that require a 'running' status

        # Check status
        if args.health:
            check_health(container)

        # Check cpu usage
        if args.cpu:
            check_cpu(container, parse_thresholds(args.cpu, units_required=False))

        # Check memory usage
        if args.memory:
            check_memory(container, parse_thresholds(args.memory, units_required=False))

        # Check uptime
        if args.uptime:
            check_uptime(container, parse_thresholds(args.uptime, include_units=False))

        # Check restart count
        if args.restarts:
            check_restarts(container, parse_thresholds(args.restarts, include_units=False))


def main():
    try:
        perform_checks(argv[1:])

        # get results to let exceptions in threads bubble out
        [x.result() for x in futures.as_completed(threads)]

    except Exception as e:
        traceback.print_exc()
        unknown("Exception raised during check': {}".format(repr(e)))
    print_results()
    exit(rc)


if __name__ == '__main__':
    main()
