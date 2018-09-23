import json
import stat
from collections import defaultdict
from datetime import datetime, timezone, timedelta

try:
    from importlib import reload
except ImportError:
    from imp import reload
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from check_docker import check_docker as cd

__author__ = 'Tim Laurence'


class FakeHttpResponse(BytesIO):
    def __init__(self, content=b'', http_code=200, headers=None, method='GET'):
        self.status = http_code
        self.code = http_code
        self.headers = headers if headers else {}
        self.method = method
        super(FakeHttpResponse, self).__init__(content)

    def getheader(self, header, default):
        return self.headers.get(header, default)


@pytest.fixture()
def check_docker_fresh():
    """
    This is used for tests that have issues with cross test interaction
    :return:
    """
    reload(cd)
    return cd


@pytest.fixture()
def check_docker():
    cd.rc = -1
    cd.timeout = 1
    cd.messages = []
    cd.performance_data = []
    cd.daemon = 'socket:///notreal'
    cd.get_url.cache_clear()
    cd.head_url.cache_clear()
    cd.DISABLE_THREADING = True
    cd.Oauth2TokenAuthHandler.auth_failure_tracker = defaultdict(int)

    def fake_exit(_=None):
        pass

    cd.exit = fake_exit
    return cd


@pytest.fixture
def check_docker_with_units(check_docker):
    check_docker.unit_adjustments = {key: 1024 ** value for key, value in
                                     check_docker.UNIT_ADJUSTMENTS_TEMPLATE.items()}
    return check_docker


def test_get_url(check_docker):
    obj = {'foo': 'bar'}
    encoded = json.dumps(obj=obj).encode('utf-8')
    expected_response = FakeHttpResponse(content=encoded, http_code=200)

    def mock_open(*args, **kwargs):
        return expected_response

    with patch('check_docker.check_docker.better_urllib_get.open', side_effect=mock_open):
        response, _ = check_docker.get_url(url='/test')
        assert response == obj


def test_head_url(check_docker):
    mock_response = FakeHttpResponse(content=b'', http_code=200, method='HEAD', headers={'test': 'test_value'})

    def mock_open(*args, **kwargs):
        return mock_response

    with patch('check_docker.check_docker.HTTPSHandler.https_open', side_effect=mock_open):
        response = check_docker.head_url(url='https://example.com/test')
        assert response.getheader('test', None) == 'test_value'


def test_head_url_with_oauth2(check_docker):
    headers1 = {
        'www-authenticate': 'Bearer realm="https://docker-auth.example.com/auth",service="token-service",scope="repository:something/something_else:pull"'}
    mock_response1 = FakeHttpResponse(method='HEAD', http_code=401, headers=headers1)

    mock_response2 = FakeHttpResponse(method='HEAD', http_code=200, headers={'test': 'test'})

    with patch('check_docker.check_docker.HTTPSHandler.https_open', side_effect=[mock_response1, mock_response2]), \
         patch('check_docker.check_docker.Oauth2TokenAuthHandler._get_outh2_token',
               return_value='test_token') as get_token:
        response = check_docker.head_url(url='https://example.com/test')
        assert response == mock_response2
        assert get_token.call_count == 1


def test_head_url_with_oauth2_loop(check_docker):
    headers = {
        'www-authenticate': 'Bearer realm="https://docker-auth.example.com/auth",service="token-service",scope="repository:something/something_else:pull"'}
    mock_response = FakeHttpResponse(method='HEAD', http_code=401, headers=headers)

    def mock_open(*args, **kwargs):
        return mock_response

    with patch('check_docker.check_docker.HTTPSHandler.https_open', side_effect=mock_open), \
         patch('check_docker.check_docker.Oauth2TokenAuthHandler._get_outh2_token',
               return_value='test_token') as get_token:
        with pytest.raises(HTTPError):
            check_docker.head_url(url='https://example.com/test')


def test_head_url_500(check_docker):
    expected_exception = HTTPError(code=500, fp=None, url='url', msg='msg', hdrs=[])
    with patch('check_docker.check_docker.HTTPSHandler.https_open', side_effect=expected_exception), \
         pytest.raises(HTTPError):
        check_docker.head_url(url='https://example.com/test')


@pytest.mark.parametrize("func", [
    'get_stats',
    'get_state',
    'get_image_info'
])
def test_get_url_calls(check_docker, func):
    # TODO
    with patch('check_docker.check_docker.get_url', return_value=({'State': 'State'}, 200)) as patched:
        getattr(check_docker, func)('container')
        assert patched.call_count == 1

@pytest.mark.parametrize("value, expected", [
    (1,["1s"]),
    (61, ["1min", "1s"]),
    (3661, ["1h", "1min", "1s"]),
    (86401, ["1d", "1s"])
])
def test_pretty_time(check_docker, value, expected):
    assert check_docker.pretty_time(value) == expected

@pytest.mark.parametrize("value, rc, messages, perf_data", [
    (1, cd.OK_RC, ['OK: container metric is 1B'], ['container_met=1B;2;3;0;10']),
    (2, cd.WARNING_RC, ['WARNING: container metric is 2B'], ['container_met=2B;2;3;0;10']),
    (3, cd.CRITICAL_RC, ['CRITICAL: container metric is 3B'], ['container_met=3B;2;3;0;10'])
])
def test_evaluate_numeric_thresholds(check_docker, value, rc, messages, perf_data):
    thresholds = cd.ThresholdSpec(warn=2, crit=3, units='B')
    check_docker.evaluate_numeric_thresholds(container='container', value=value, name='metric', short_name='met',
                                             min=0, max=10, thresholds=thresholds
                                             )
    assert check_docker.rc == rc
    assert check_docker.messages == messages
    assert check_docker.performance_data == perf_data


@pytest.mark.parametrize('func,arg,rc,messages',
                         (
                                 ('ok', "OK test", cd.OK_RC, ['OK: OK test']),
                                 ('warning', "WARN test", cd.WARNING_RC, ['WARNING: WARN test']),
                                 ('critical', "CRIT test", cd.CRITICAL_RC, ['CRITICAL: CRIT test']),
                                 ('unknown', "UNKNOWN test", cd.UNKNOWN_RC, ['UNKNOWN: UNKNOWN test']),
                         ))
def test_status_update(check_docker, func, arg, rc, messages):
    getattr(check_docker, func)(arg)
    assert check_docker.rc == rc
    assert check_docker.messages == messages


@pytest.mark.parametrize('input, units_required, expected', (
        ('1:2:3', True, cd.ThresholdSpec(warn=1, crit=2, units='3')),
        ('1:2', False, cd.ThresholdSpec(warn=1, crit=2, units='')),
        ('1:2:3', False, cd.ThresholdSpec(warn=1, crit=2, units='3')),

))
def test_parse_thresholds(check_docker, input, units_required, expected):
    result = check_docker.parse_thresholds(input, units_required=units_required)
    assert expected == result


@pytest.mark.parametrize('spec, kwargs, exception', (
        ('1:2', {}, ValueError),
        ('1:2:b', {'include_units': False}, ValueError),
        ('1:2', {'include_units': True}, ValueError),
        ("1", {}, IndexError),
        (":1", {}, ValueError),
        (":1:c", {}, ValueError),
        ("1:", {}, ValueError),
        ("1::c", {}, ValueError),
        ('1:2:', {'units_required': True}, ValueError),
        ("a:1:c", {}, ValueError),
        ("1:b:c", {}, ValueError),
)
                         )
def test_parse_thresholds_exceptions(check_docker, spec, kwargs, exception):
    with pytest.raises(exception):
        check_docker.parse_thresholds(spec, **kwargs)


def test_set_rc(check_docker):
    # Can I do a basic set
    check_docker.set_rc(check_docker.OK_RC)
    assert check_docker.rc == check_docker.OK_RC

    # Does it prevent downgrades of rc
    check_docker.set_rc(check_docker.WARNING_RC)
    assert check_docker.rc == check_docker.WARNING_RC
    check_docker.set_rc(check_docker.OK_RC)
    assert check_docker.rc == check_docker.WARNING_RC


@pytest.mark.parametrize('response, expected_status', (
        ({'State': {'Running': True}}, cd.OK_RC),
        ({'State': {'Status': 'stopped'}}, cd.CRITICAL_RC),
        ({'State': {'Running': False}}, cd.CRITICAL_RC),
        ({'State': {'foo': False}}, cd.UNKNOWN_RC)
))
def test_check_status(check_docker, response, expected_status):
    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    with patch('check_docker.check_docker.better_urllib_get.open', side_effect=mock_response):
        check_docker.check_status(container='container', desired_state='running')
        assert check_docker.rc == expected_status


@pytest.mark.parametrize('response, expected_status', (
        ({'State': {'Health': {'Status': 'healthy'}, 'Running': True}}, cd.OK_RC),
        ({'State': {'Health': {'Status': 'unhealthy'}, 'Running': True}}, cd.CRITICAL_RC),
        ({'State': {'Running': True}}, cd.UNKNOWN_RC),
        ({'State': {'Health': {}, 'Running': True}}, cd.UNKNOWN_RC),
        ({'State': {'Health': {'Status': 'starting'}, 'Running': True}}, cd.UNKNOWN_RC)
))
def test_check_health(check_docker, response, expected_status):
    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    with patch('check_docker.check_docker.better_urllib_get.open', side_effect=mock_response):
        check_docker.check_health(container='container')
        assert check_docker.rc == expected_status


@pytest.mark.parametrize('memory_stats, warn, crit, units, expected_status', (
        ({'limit': 10, 'usage': 1, 'stats': {'total_cache': 1}}, 1, 2, 'B', cd.OK_RC),
        ({'limit': 10, 'usage': 2, 'stats': {'total_cache': 1}}, 1, 2, 'B', cd.WARNING_RC),
        ({'limit': 10, 'usage': 3, 'stats': {'total_cache': 1}}, 1, 2, 'B', cd.CRITICAL_RC),
        ({'limit': 10, 'usage': 1, 'stats': {'total_cache': 1}}, 20, 30, '%', cd.OK_RC),
        ({'limit': 10, 'usage': 3, 'stats': {'total_cache': 1}}, 20, 30, '%', cd.WARNING_RC),
        ({'limit': 10, 'usage': 4, 'stats': {'total_cache': 1}}, 20, 30, '%', cd.CRITICAL_RC),
        ({'limit': 10, 'usage': 4, 'stats': {'total_cache': 1}}, 20, 30, 'BAD_UNITS', cd.UNKNOWN_RC),
))
def test_check_memory(check_docker_with_units, memory_stats, warn, crit, units, expected_status):
    response = {
        'memory_stats': memory_stats,
        'State': {'Running': True}
    }

    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    with patch('check_docker.check_docker.better_urllib_get.open', side_effect=mock_response):
        thresholds = cd.ThresholdSpec(warn=warn, crit=crit, units=units)
        check_docker_with_units.check_memory(container='container', thresholds=thresholds)
        assert check_docker_with_units.rc == expected_status


cpu_param_fields = 'host_config, cpu_stats, precpu_stats, warn, crit, expected_status, expected_percent'
cpu_parm_tests = (({"NanoCpus": 1000000000, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'percpu_usage': [15], 'total_usage': 15}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'online_cpus': 1, 'system_cpu_usage': 0},
                   10, 20, cd.OK_RC, 5),
                  ({"NanoCpus": 1000000000, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'percpu_usage': [25], 'total_usage': 25}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'online_cpus': 1, 'system_cpu_usage': 0},
                   10, 20, cd.WARNING_RC, 15),
                  ({"NanoCpus": 1000000000, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'percpu_usage': [35], 'total_usage': 35}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'online_cpus': 1, 'system_cpu_usage': 0},
                   10, 20, cd.CRITICAL_RC, 25),
                  ({"NanoCpus": 0, "CpuPeriod": 0, "CpuQuota": 10000},
                   {'cpu_usage': {'percpu_usage': [15], 'total_usage': 15}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'online_cpus': 1, 'system_cpu_usage': 0},
                   10, 20, cd.CRITICAL_RC, 50),
                  ({"NanoCpus": 0, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'percpu_usage': [35], 'total_usage': 35}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'online_cpus': 1, 'system_cpu_usage': 0},
                   10, 20, cd.CRITICAL_RC, 25),
                  ({"NanoCpus": 0, "CpuPeriod": 1, "CpuQuota": 2},
                   {'cpu_usage': {'percpu_usage': [35], 'total_usage': 35}, 'online_cpus': 1, 'system_cpu_usage': 100},
                   {'cpu_usage': {'percpu_usage': [10], 'total_usage': 10}, 'system_cpu_usage': 0},
                   10, 20, cd.CRITICAL_RC, 25),
                  ({"NanoCpus": 0, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'total_usage': 36}, 'online_cpus': 2, 'system_cpu_usage': 200},
                   {'cpu_usage': {'total_usage': 10}, 'system_cpu_usage': 0},
                   10, 20, cd.WARNING_RC, 13),
                  ({"NanoCpus": 0, "CpuPeriod": 0, "CpuQuota": 0},
                   {'cpu_usage': {'percpu_usage': [35, 1], 'total_usage': 36}, 'system_cpu_usage': 200},
                   {'cpu_usage': {'total_usage': 10}, 'system_cpu_usage': 0},
                   10, 20, cd.WARNING_RC, 13
                   )
                  )


@pytest.mark.parametrize(cpu_param_fields, cpu_parm_tests)
def test_check_cpu(check_docker, host_config, cpu_stats, precpu_stats, warn, crit, expected_status, expected_percent):
    container_stats = {
        'cpu_stats': cpu_stats,
        'precpu_stats': precpu_stats
    }
    container_info = {
        'State': {'Running': True},
        "HostConfig": host_config
    }

    def mock_stats_response(*args, **kwargs):
        return container_stats

    def mock_info_response(*args, **kwargs):
        return container_info

    with patch('check_docker.check_docker.get_stats', side_effect=mock_stats_response), \
         patch('check_docker.check_docker.get_container_info', side_effect=mock_info_response):
        thresholds = cd.ThresholdSpec(warn=warn, crit=crit, units=None)
        check_docker.check_cpu(container='container', thresholds=thresholds)
        assert check_docker.rc == expected_status


@pytest.mark.parametrize(cpu_param_fields, cpu_parm_tests)
def test_calculate_cpu(check_docker, host_config, cpu_stats, precpu_stats, warn, crit, expected_status,
                       expected_percent):
    container_stats = {
        'cpu_stats': cpu_stats,
        'precpu_stats': precpu_stats
    }
    container_info = {
        'State': {'Running': True},
        "HostConfig": host_config
    }

    pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
    assert pecentage == expected_percent


def test_require_running(check_docker):
    """ This confirms the 'require_running decorator is working properly with a stopped container"""
    container_info = {'RestartCount': 0, 'State': {'Running': False}}

    def mock_info_response(*args, **kwargs):
        return container_info

    with patch('check_docker.check_docker.get_container_info', side_effect=mock_info_response):
        thresholds = cd.ThresholdSpec(warn=1, crit=2, units='')
        check_docker.check_restarts(container='container', thresholds=thresholds)
        assert check_docker.rc == check_docker.CRITICAL_RC


@pytest.mark.parametrize("restarts, expected_status", (
        (0, cd.OK_RC),
        (1, cd.WARNING_RC),
        (3, cd.CRITICAL_RC),
))
def test_restarts(check_docker, restarts, expected_status):
    container_info = {'RestartCount': restarts, 'State': {'Running': True}}

    def mock_info_response(*args, **kwargs):
        return container_info

    with patch('check_docker.check_docker.get_container_info', side_effect=mock_info_response):
        thresholds = cd.ThresholdSpec(warn=1, crit=2, units='')
        check_docker.check_restarts(container='container', thresholds=thresholds)
        assert check_docker.rc == expected_status


@pytest.mark.parametrize("uptime, warn, crit, expected_status", (
        (timedelta(seconds=0), 10, 5, cd.CRITICAL_RC),
        (timedelta(seconds=9), 10, 1, cd.WARNING_RC),
        (timedelta(seconds=10), 2, 1, cd.OK_RC),
        (timedelta(days=1, seconds=0), 2, 1, cd.OK_RC)
))
def test_check_uptime1(check_docker, uptime, warn, crit, expected_status):
    time = datetime.now(tz=timezone.utc) - uptime
    time_str = time.strftime("%Y-%m-%dT%H:%M:%S.0000000000Z")
    json_results = {
        'State': {'StartedAt': time_str,
                  'Running': True},
    }

    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=json_results).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    with patch('check_docker.check_docker.better_urllib_get.open', side_effect=mock_response):
        thresholds = cd.ThresholdSpec(warn=warn, crit=crit, units='')
        check_docker.check_uptime(container='container', thresholds=thresholds)
        assert check_docker.rc == expected_status


sample_containers = [
    {'Names': ['/name1']},
    {'Names': ['/name2']}]


@pytest.fixture
def sample_containers_json():
    return sample_containers


@pytest.fixture
def mock_get_container_info():
    def mock(id):
        return {'Name': sample_containers[id]}

    return mock


def test_args_help(check_docker, capsys):
    args = tuple()
    check_docker.process_args(args=args)
    out, err = capsys.readouterr()
    assert 'usage: ' in out


@pytest.mark.parametrize("args, expected_value, default_value", (
        (('--timeout', '9999'), 9999, cd.DEFAULT_TIMEOUT),
        (('--containers', 'foo', 'bar'), ['foo', 'bar'], ['all']),
        (('--present',), True, False),
        (('--threads', '23'), 23, cd.DISABLE_THREADING),
        (('--cpu', 'non-default'), 'non-default', None),
        (('--memory', 'non-default'), 'non-default', None),
        (('--status', 'non-default'), 'non-default', None),
        (('--health',), True, None),
        (('--uptime', 'non-default'), 'non-default', None),
        (('--version',), True, None),
        (('--insecure-registries', 'non-default'), ['non-default'], None),
        (('--restarts', 'non-default'), 'non-default', None),
))
def test_args(check_docker, args, expected_value, default_value):
    attrib_name = args[0][2:].replace('-', '_')  # Strip the -- off the first arg
    if default_value:
        default_result = check_docker.process_args(args=[])
        assert getattr(default_result, attrib_name) == default_value

    result = check_docker.process_args(args=args)
    assert getattr(result, attrib_name) == expected_value


def test_args_containers_blank(check_docker):
    args = ('--containers',)
    with pytest.raises(SystemExit):
        check_docker.process_args(args=args)


def test_args_connection(check_docker):
    args = ('--connection', '/foo')
    result = check_docker.process_args(args=args)
    assert result.connection == '/foo'
    assert check_docker.daemon == 'socket:///foo:'

    args = ('--connection', 'foo.com/bar')
    result = check_docker.process_args(args=args)
    assert result.connection == 'foo.com/bar'
    assert check_docker.daemon == 'http://foo.com/bar'


def test_args_secure_connection(check_docker):
    check_docker.rc = -1
    args = ('--secure-connection', 'non-default')
    result = check_docker.process_args(args=args)
    assert result.secure_connection == 'non-default'

    args = ('--secure-connection', 'foo.com/bar')
    result = check_docker.process_args(args=args)
    assert result.secure_connection == 'foo.com/bar'
    assert check_docker.daemon == 'https://foo.com/bar'


@pytest.mark.parametrize('args', (
        ('--connection', 'non-default', '--secure-connection', 'non-default'),
        ('--binary_units', '--decimal_units')
))
def test_exclusive_args(check_docker, args):
    with pytest.raises(SystemExit):
        check_docker.process_args(args)


def test_units_base_uninitialized(check_docker_fresh):
    # Assert value is driven by argprase results, i.e. there is no default value
    assert check_docker_fresh.unit_adjustments is None, "unit_adjustments has no sensible default without knowing the base"


def test_units_base_initialized(check_docker_fresh):
    # Confirm default value is set
    parsed_args = check_docker_fresh.process_args([])
    assert parsed_args.units_base == 1024, "units_base should default to 1024"


@pytest.mark.parametrize('arg, one_kb', (
        ('--binary_units', 1024),
        ('--decimal_units', 1000)
))
def test_units_base(check_docker, fs, arg, one_kb):
    # Confirm value is updated by argparse flags
    parsed_args = check_docker.process_args([arg])
    assert parsed_args.units_base == one_kb, "units_base should be influenced by units flags"

    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_docker.get_containers', return_value=['test']), \
         patch('check_docker.check_docker.get_stats',
               return_value={'memory_stats': {'limit': one_kb, 'usage': one_kb, 'stats': {'total_cache': 0}}}), \
         patch('check_docker.check_docker.get_state', return_value={'Running': True}):
        check_docker.perform_checks(['--memory', '0:0:KB', arg])

    # Confirm unit adjustment table was updated by argument
    assert check_docker.unit_adjustments['KB'] == one_kb

    # Confirm output shows unit conversion specified by arg
    assert check_docker.performance_data == ['test_mem=1.0KB;0;0;0;1.0']


def test_missing_check(check_docker):
    check_docker.rc = -1
    args = tuple()
    result = check_docker.process_args(args=args)
    assert check_docker.no_checks_present(result)


def test_present_check(check_docker):
    check_docker.rc = -1
    args = ('--status', 'running')
    result = check_docker.process_args(args=args)
    assert not check_docker.no_checks_present(result)


def test_disallow_present_without_containers(check_docker):
    args = ('--cpu', '0:0', '--present')
    with patch('check_docker.check_docker.get_containers') as patched_get_containers:
        with patch('check_docker.check_docker.unknown') as patched_unknown:
            check_docker.perform_checks(args)
            assert patched_unknown.call_count == 1
            assert patched_get_containers.call_count == 0


def test_get_containers_1(check_docker, sample_containers_json, mock_get_container_info):
    with patch('check_docker.check_docker.get_url', return_value=(sample_containers_json, 200)), \
         patch('check_docker.check_docker.get_container_info', side_effect=mock_get_container_info):
        container_list = check_docker.get_containers('all', False)
        assert container_list == {'name1', 'name2'}


def test_get_containers_2(check_docker, sample_containers_json, mock_get_container_info):
    with patch('check_docker.check_docker.get_url', return_value=(sample_containers_json, 200)):
        with patch('check_docker.check_docker.get_container_info', side_effect=mock_get_container_info):
            container_list = check_docker.get_containers(['name.*'], False)
            assert container_list == {'name1', 'name2'}


def test_get_containers_3(check_docker, sample_containers_json, mock_get_container_info):
    check_docker.rc = -1
    with patch('check_docker.check_docker.get_url', return_value=(sample_containers_json, 200)), \
         patch('check_docker.check_docker.unknown') as patched, \
            patch('check_docker.check_docker.get_container_info', side_effect=mock_get_container_info):
        container_list = check_docker.get_containers({'foo'}, False)
        assert container_list == set()
        assert patched.call_count == 0


def test_get_containers_4(check_docker, sample_containers_json, mock_get_container_info):
    check_docker.rc = -1
    with patch('check_docker.check_docker.get_url', return_value=(sample_containers_json, 200)):
        with patch('check_docker.check_docker.critical') as patched, \
                patch('check_docker.check_docker.get_container_info', side_effect=mock_get_container_info):
            container_list = check_docker.get_containers({'foo'}, True)
            assert container_list == set()
            assert patched.call_count == 1


def test_socketfile_failure_false(check_docker, fs):
    fs.CreateFile('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ('--status', 'running', '--connection', '/tmp/socket')
    result = check_docker.process_args(args=args)
    assert not check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_result(check_docker):
    # Confirm bad socket results in uknown status

    args = ('--cpu', '0:0', '--connection', '/tmp/missing')
    with patch('check_docker.check_docker.get_url', return_value=(['thing1'], 200)):
        with patch('check_docker.check_docker.unknown') as patched:
            check_docker.perform_checks(args)
            assert patched.call_count == 1


def test_socketfile_failure_filetype(check_docker, fs):
    fs.CreateFile('/tmp/not_socket', contents='testing')
    args = ('--status', 'running', '--connection', '/tmp/not_socket')
    result = check_docker.process_args(args=args)
    assert check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_missing(check_docker, fs):
    args = ('--status', 'running', '--connection', '/tmp/missing')
    result = check_docker.process_args(args=args)
    assert check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unwriteable(check_docker, fs):
    fs.CreateFile('/tmp/unwritable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--status', 'running', '--connection', '/tmp/unwritable')
    result = check_docker.process_args(args=args)
    assert check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unreadable(check_docker, fs):
    fs.CreateFile('/tmp/unreadable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--status', 'running', '--connection', '/tmp/unreadable')
    result = check_docker.process_args(args=args)
    assert check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_http(check_docker, fs):
    fs.CreateFile('/tmp/http', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--status', 'running', '--connection', 'http://127.0.0.1')
    result = check_docker.process_args(args=args)
    assert not check_docker.socketfile_permissions_failure(parsed_args=result)


def test_perform_with_no_containers(check_docker, fs):
    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--cpu', '0:0']
    with patch('check_docker.check_docker.get_url', return_value=([], 200)):
        with patch('check_docker.check_docker.unknown') as patched:
            check_docker.perform_checks(args)
            assert patched.call_count == 1


def test_perform_with_uncaught_exception(check_docker, fs):
    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_docker.get_url', return_value=([{'Names': ('/thing1',)}], 200)), \
         patch('check_docker.check_docker.check_cpu', side_effect=Exception("Oh no!")), \
         patch('check_docker.check_docker.argv', side_effect=['', '--cpu', '0:0']), \
         patch('check_docker.check_docker.unknown') as patched:
        check_docker.main()
    assert patched.call_count == 1


@pytest.mark.parametrize("args, called", (
        (['--cpu', '0:0'], 'check_cpu'),
        (['--memory', '0:0'], 'check_memory'),
        (['--health'], 'check_health'),
        (['--restarts', '1:1'], 'check_restarts'),
        (['--status', 'running'], 'check_status'),
        (['--uptime', '0:0'], 'check_uptime'),
        (['--version'], 'check_version'),
        ([], 'unknown')
))
def test_perform(check_docker, fs, args, called):
    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_docker.get_containers', return_value=['thing1']):
        with patch('check_docker.check_docker.' + called) as patched:
            check_docker.perform_checks(args)
            assert patched.call_count == 1


@pytest.mark.parametrize("messages, perf_data, expected", (
        ([], [], ''),
        (['TEST'], [], 'TEST'),
        (['FOO', 'BAR'], [], 'FOO; BAR'),
        (['FOO', 'BAR'], ['1;2;3;4;'], 'FOO; BAR|1;2;3;4;')
))
def test_print_results(check_docker, capsys, messages, perf_data, expected):
    check_docker.messages = messages
    check_docker.performance_data = perf_data
    check_docker.print_results()
    out, err = capsys.readouterr()
    assert out.strip() == expected


@pytest.mark.parametrize('url, expected', (
        ("short", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/short", tag="latest",
                               full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/short:latest")),

        ("simple/name", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="simple/name", tag="latest",
                                     full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/simple/name:latest")),
        ("library/ubuntu", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/ubuntu", tag="latest",
                                        full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/ubuntu:latest")),
        ("docker/stevvooe/app",
         cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="docker/stevvooe/app", tag="latest",
                      full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/docker/stevvooe/app:latest")),
        ("aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb",
         cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb",
                      tag="latest",
                      full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/aa/aa/aa/aa/aa/aa/aa/aa/aa/bb/bb/bb/bb/bb/bb:latest")),
        ("aa/aa/bb/bb/bb", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="aa/aa/bb/bb/bb", tag="latest",
                                        full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/aa/aa/bb/bb/bb:latest")),
        ("a/a/a/a", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="a/a/a/a", tag="latest",
                                 full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/a/a/a/a:latest")),
        ("a", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/a", tag="latest",
                           full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/a:latest")),
        ("a/aa", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="a/aa", tag="latest",
                              full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/a/aa:latest")),
        ("a/aa/a", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="a/aa/a", tag="latest",
                                full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/a/aa/a:latest")),
        ("foo.com", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/foo.com", tag="latest",
                                 full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/foo.com:latest")),
        ("foo.com:8080/bar",
         cd.ImageName(registry="foo.com:8080", name="bar", tag="latest", full_name="foo.com:8080/bar:latest")),
        ("foo.com/bar", cd.ImageName(registry="foo.com", name="bar", tag="latest", full_name="foo.com/bar:latest")),
        ("foo.com/bar/baz",
         cd.ImageName(registry="foo.com", name="bar/baz", tag="latest", full_name="foo.com/bar/baz:latest")),

        ("localhost:8080/bar",
         cd.ImageName(registry="localhost:8080", name="bar", tag="latest", full_name="localhost:8080/bar:latest")),
        ("sub-dom1.foo.com/bar/baz/quux", cd.ImageName(registry="sub-dom1.foo.com", name="bar/baz/quux", tag="latest",
                                                       full_name="sub-dom1.foo.com/bar/baz/quux:latest")),
        ("blog.foo.com/bar/baz",
         cd.ImageName(registry="blog.foo.com", name="bar/baz", tag="latest", full_name="blog.foo.com/bar/baz:latest")),
        ("aa-a/a", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="aa-a/a", tag="latest",
                                full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/aa-a/a:latest")),
        ("foo_bar", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/foo_bar", tag="latest",
                                 full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/foo_bar:latest")),
        ("foo_bar.com", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/foo_bar.com", tag="latest",
                                     full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/foo_bar.com:latest")),
        ("foo.com/foo_bar",
         cd.ImageName(registry="foo.com", name="foo_bar", tag="latest", full_name="foo.com/foo_bar:latest")),
        ("b.gcr.io/test.example.com/my-app",
         cd.ImageName(registry="b.gcr.io", name="test.example.com/my-app", tag="latest",
                      full_name="b.gcr.io/test.example.com/my-app:latest")),
        ("xn--n3h.com/myimage",
         cd.ImageName(registry="xn--n3h.com", name="myimage", tag="latest", full_name="xn--n3h.com/myimage:latest")),
        ("xn--7o8h.com/myimage",
         cd.ImageName(registry="xn--7o8h.com", name="myimage", tag="latest", full_name="xn--7o8h.com/myimage:latest")),
        ("example.com/xn--7o8h.com/myimage",
         cd.ImageName(registry="example.com", name="xn--7o8h.com/myimage", tag="latest",
                      full_name="example.com/xn--7o8h.com/myimage:latest")),
        ("example.com/some_separator__underscore/myimage",
         cd.ImageName(registry="example.com", name="some_separator__underscore/myimage", tag="latest",
                      full_name="example.com/some_separator__underscore/myimage:latest")),
        ("do__cker/docker", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="do__cker/docker", tag="latest",
                                         full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/do__cker/docker:latest")),
        ("b.gcr.io/test.example.com/my-app",
         cd.ImageName(registry="b.gcr.io", name="test.example.com/my-app", tag="latest",
                      full_name="b.gcr.io/test.example.com/my-app:latest")),
        ("registry.io/foo/project--id.module--name.ver---sion--name",
         cd.ImageName(registry="registry.io", name="foo/project--id.module--name.ver---sion--name", tag="latest",
                      full_name="registry.io/foo/project--id.module--name.ver---sion--name:latest")),
        ("Asdf.com/foo/bar",
         cd.ImageName(registry="Asdf.com", name="foo/bar", tag="latest", full_name="Asdf.com/foo/bar:latest")),
        ("host.tld:12/name:tag",
         cd.ImageName(registry="host.tld:12", name="name", tag="tag", full_name="host.tld:12/name:tag")),
        ("host.tld/name:tag", cd.ImageName(registry="host.tld", name="name", tag="tag", full_name="host.tld/name:tag")),
        ("name/name:tag", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="name/name", tag="tag",
                                       full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/name/name:tag")),
        ("name:tag", cd.ImageName(registry=cd.DEFAULT_PUBLIC_REGISTRY, name="library/name", tag="tag",
                                  full_name=cd.DEFAULT_PUBLIC_REGISTRY + "/library/name:tag")),
        ("host:21/name:tag", cd.ImageName(registry='host:21', name="name", tag="tag",
                                          full_name="host:21/name:tag")),
))
def test_parse_image_name(check_docker, url, expected):
    parsed_name = check_docker.parse_image_name(url)
    assert parsed_name == expected


def test_get_manifest_auth_token(check_docker):
    obj = {'token': 'test'}
    encoded = json.dumps(obj=obj).encode('utf-8')
    expected_response = FakeHttpResponse(content=encoded, http_code=200)
    with patch('check_docker.check_docker.request.urlopen', return_value=expected_response):
        www_authenticate_header = 'Bearer realm="https://example.com/token",service="example.com",scope="repository:test:pull"'
        token = check_docker.Oauth2TokenAuthHandler._get_outh2_token(www_authenticate_header)
        assert token == 'test'


def test_get_container_image_urls(check_docker):
    container_response = {'Image': 'test'}
    image_response = {'RepoTags': ['test']}
    with patch('check_docker.check_docker.get_container_info', return_value=container_response), \
         patch('check_docker.check_docker.get_image_info', return_value=image_response):
        urls = check_docker.get_container_image_urls('container')
        assert urls == ['test']


@pytest.mark.parametrize('image_url, expected_normal_url', (
        ('foo', 'https://' + cd.DEFAULT_PUBLIC_REGISTRY + '/v2/library/foo/manifests/latest'),
        ('insecure.com/foo', 'http://insecure.com/v2/foo/manifests/latest'),
))
def test_normalize_image_name_to_manifest_url(check_docker, image_url, expected_normal_url):
    insecure_registries = ('insecure.com',)
    normal_url, _ = check_docker.normalize_image_name_to_manifest_url(image_url, insecure_registries)
    assert normal_url == expected_normal_url


@pytest.mark.parametrize('image_response, expected_digest', (
        ({'RepoDigests': []}, None),
        ({'RepoDigests': ['name@AAAAAA']}, 'AAAAAA'),
))
def test_get_container_digest(check_docker, image_response, expected_digest):
    container_response = {'Image': 'test'}
    with patch('check_docker.check_docker.get_container_info', return_value=container_response), \
         patch('check_docker.check_docker.get_image_info', return_value=image_response):
        digest = check_docker.get_container_digest('container')
        assert digest == expected_digest


def test_get_digest_from_registry_no_auth(check_docker):
    response = FakeHttpResponse(content=b"", http_code=200, headers={'Docker-Content-Digest': "test_token"})

    with patch('check_docker.check_docker.head_url', return_value=response):
        digest = check_docker.get_digest_from_registry('https://example.com/v2/test/manifests/lastest')
        assert digest == "test_token"


def test_get_digest_from_registry_missing_digest(check_docker):
    response = FakeHttpResponse(content=b"", http_code=401, headers={
        'Www-Authenticate': 'Bearer realm="https://example.com/token",service="example.com",scope="repository:test:pull"'})

    with patch('check_docker.check_docker.head_url', return_value=response):
        with pytest.raises(check_docker.RegistryError):
            check_docker.get_digest_from_registry('https://example.com/v2/test/manifests/lastest')


@pytest.mark.parametrize('local_container_digest,registry_container_digest, image_urls, expected_rc', (
        ('AAAA', 'AAAA', ('example.com/foo',), cd.OK_RC),
        ('AAAA', 'BBBB', ('example.com/foo',), cd.CRITICAL_RC),
        (None, '', ('example.com/foo',), cd.UNKNOWN_RC),
        ('AAAA', 'AAAA', ('example.com/foo', 'example.com/bar'), cd.UNKNOWN_RC),
        ('AAAA', 'AAAA', tuple(), cd.UNKNOWN_RC),
))
def test_check_version(check_docker, local_container_digest, registry_container_digest, image_urls, expected_rc):
    with patch('check_docker.check_docker.get_container_digest', return_value=local_container_digest), \
         patch('check_docker.check_docker.get_container_image_urls', return_value=image_urls), \
         patch('check_docker.check_docker.get_digest_from_registry', return_value=registry_container_digest):
        check_docker.check_version('container', tuple())
        assert check_docker.rc == expected_rc


def test_check_version_missing_digest(check_docker):
    with patch('check_docker.check_docker.get_container_digest', return_value='AAA'), \
         patch('check_docker.check_docker.get_container_image_urls', return_value=('example.com/foo',)), \
         patch('check_docker.check_docker.get_digest_from_registry',
               side_effect=check_docker.RegistryError(response=None)):
        check_docker.check_version('container', tuple())
        assert check_docker.rc == cd.UNKNOWN_RC


def test_check_version_not_tls(check_docker):
    class Reason():
        reason = 'UNKNOWN_PROTOCOL'

    exception = URLError(reason=Reason)
    with patch('check_docker.check_docker.get_container_digest', return_value='AAA'), \
         patch('check_docker.check_docker.get_container_image_urls', return_value=('example.com/foo',)), \
         patch('check_docker.check_docker.get_digest_from_registry', side_effect=exception):
        check_docker.check_version('container', tuple())
        assert check_docker.rc == cd.UNKNOWN_RC
        assert 'TLS error' in check_docker.messages[0]


def test_check_version_no_such_host(check_docker):
    class Reason():
        strerror = 'nodename nor servname provided, or not known'

    exception = URLError(reason=Reason)
    with patch('check_docker.check_docker.get_container_digest', return_value='AAA'), \
         patch('check_docker.check_docker.get_container_image_urls', return_value=('example.com/foo',)), \
         patch('check_docker.check_docker.get_digest_from_registry', side_effect=exception):
        check_docker.check_version('container', tuple())
        assert check_docker.rc == cd.UNKNOWN_RC
        assert 'Cannot reach registry' in check_docker.messages[0]


def test_check_version_exception(check_docker):
    # Unhandled exceptions should be passed on
    exception = URLError(reason=None)
    with patch('check_docker.check_docker.get_container_digest', return_value='AAA'), \
         patch('check_docker.check_docker.get_container_image_urls', return_value=('example.com/foo',)), \
         patch('check_docker.check_docker.get_digest_from_registry', side_effect=exception), \
         pytest.raises(URLError):
        check_docker.check_version('container', tuple())


@pytest.mark.parametrize('names', (
        (('\\a', 'a\\b'),),
        (('\\a'),),
        (('a\\b', '\\a'),)
))
def test_get_ps_name_ok(check_docker, names):
    assert check_docker.ps_name(names) == 'a'


@pytest.mark.parametrize('names', (
        ('a\\b'),
        set(),
        ('a\\b', 'b\\a'),
        ('\\b', '\\a'),
))
def test_get_ps_name_ok(check_docker, names):
    with pytest.raises(NameError):
        check_docker.get_ps_name(names)
