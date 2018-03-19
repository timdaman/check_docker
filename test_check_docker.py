import json
from io import BytesIO
import stat
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
from importlib.machinery import SourceFileLoader
from urllib import request

cd = SourceFileLoader('check_docker', './check_docker').load_module()

__author__ = 'tim'


class FakeHttpResponse(BytesIO):
    def __init__(self, content, http_code, headers=None):
        self.status = http_code
        self.headers = headers if headers else {}
        super(FakeHttpResponse, self).__init__(content)

    def getheader(self, header, default):
        return self.headers.get(header, default)


@pytest.fixture
def check_docker():
    # This is needed because `check_docker` does not end a a .py so it won't be found by default
    check_docker = SourceFileLoader('check_docker', './check_docker').load_module()
    check_docker.rc = -1
    check_docker.timeout = 1
    check_docker.messages = []
    check_docker.performance_data = []
    check_docker.daemon = 'socket:///notreal'
    check_docker.get_url.cache_clear()

    return check_docker


@pytest.fixture
def check_docker_with_units(check_docker):
    check_docker.unit_adjustments = {key: 1024 ** value for key, value in
                                     check_docker.UNIT_ADJUSTMENTS_TEMPLATE.items()}
    return check_docker


def test_get_url(check_docker, monkeypatch):
    obj = {'foo': 'bar'}
    encoded = json.dumps(obj=obj).encode('utf-8')
    expected_response = FakeHttpResponse(content=encoded, http_code=200)

    def mock_open(*args, **kwargs):
        return expected_response

    monkeypatch.setattr(check_docker.better_urllib_get, 'open', value=mock_open)
    response, _ = check_docker.get_url(url='/test')
    assert response == obj


@pytest.mark.parametrize("func", [
    'get_stats',
    'get_state',
    'get_image_info'
])
def test_get_url_calls(check_docker, func):
    # TODO
    with patch('check_docker.get_url', return_value=({'State': 'State'}, 200)) as patched:
        getattr(check_docker, func)('container')
        assert patched.call_count == 1


@pytest.mark.parametrize("value, rc, messages, perf_data", [
    (1, cd.OK_RC, ['OK: container metric is 1B'], ['container_met=1B;2;3;0;10']),
    (2, cd.WARNING_RC, ['WARNING: container metric is 2B'], ['container_met=2B;2;3;0;10']),
    (3, cd.CRITICAL_RC, ['CRITICAL: container metric is 3B'], ['container_met=3B;2;3;0;10'])
])
def test_evaluate_numeric_thresholds(check_docker, value, rc, messages, perf_data):
    check_docker.evaluate_numeric_thresholds(container='container',
                                             value=value,
                                             warn=2,
                                             crit=3,
                                             name='metric',
                                             short_name='met',
                                             min=0,
                                             max=10,
                                             units='B'
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
        ('1:2:3', True, (1, 2, '3')),
        ('1:2', False, (1, 2, None)),
        ('1:2:3', False, (1, 2, '3')),

))
def test_parse_thresholds(check_docker, input, units_required, expected):
    result = check_docker.parse_thresholds(input, units_required=units_required)
    assert expected == tuple(result)


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
def test_check_status(monkeypatch, check_docker, response, expected_status):
    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    monkeypatch.setattr(check_docker.better_urllib_get, 'open', value=mock_response)
    check_docker.check_status(container='container', desired_state='running')
    assert check_docker.rc == expected_status


@pytest.mark.parametrize('response, expected_status', (
        ({'State': {'Health': {'Status': 'healthy'}, 'Running': True}}, cd.OK_RC),
        ({'State': {'Health': {'Status': 'unhealthy'}, 'Running': True}}, cd.CRITICAL_RC),
        ({'State': {'Running': True}}, cd.UNKNOWN_RC),
        ({'State': {'Health': {}, 'Running': True}}, cd.UNKNOWN_RC),
        ({'State': {'Health': {'Status': 'starting'}, 'Running': True}}, cd.UNKNOWN_RC)
))
def test_check_health(monkeypatch, check_docker, response, expected_status):
    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    monkeypatch.setattr(check_docker.better_urllib_get, 'open', value=mock_response)
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
def test_check_memory(monkeypatch, check_docker_with_units, memory_stats, warn, crit, units, expected_status):
    response = {
        'memory_stats': memory_stats,
        'State': {'Running': True}
    }

    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=response).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    monkeypatch.setattr(check_docker_with_units.better_urllib_get, 'open', value=mock_response)
    check_docker_with_units.check_memory(container='container', warn=warn, crit=crit, units=units)
    assert check_docker_with_units.rc == expected_status


cpu_param_fields = 'host_config, cpu_stats, precpu_stats, warn, crit, expected_status, exspected_percent'
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
def test_check_cpu(monkeypatch, check_docker, host_config, cpu_stats, precpu_stats, warn, crit, expected_status,
                   exspected_percent):
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

    monkeypatch.setattr(check_docker, 'get_stats', value=mock_stats_response)
    monkeypatch.setattr(check_docker, 'get_container_info', value=mock_info_response)

    check_docker.check_cpu(container='container', warn=warn, crit=crit)
    assert check_docker.rc == expected_status


@pytest.mark.parametrize(cpu_param_fields, cpu_parm_tests)
def test_calculate_cpu(check_docker, host_config, cpu_stats, precpu_stats, warn, crit, expected_status,
                       exspected_percent):
    container_stats = {
        'cpu_stats': cpu_stats,
        'precpu_stats': precpu_stats
    }
    container_info = {
        'State': {'Running': True},
        "HostConfig": host_config
    }

    pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
    assert pecentage == exspected_percent


def test_require_running(check_docker, monkeypatch):
    """ This confirms the 'require_running decorator is working properly with a stopped container"""
    container_info = {'RestartCount': 0, 'State': {'Running': False}}

    def mock_info_response(*args, **kwargs):
        return container_info

    monkeypatch.setattr(check_docker, 'get_container_info', value=mock_info_response)

    check_docker.check_restarts(container='container', warn=1, crit=2)
    assert check_docker.rc == check_docker.CRITICAL_RC


@pytest.mark.parametrize("restarts, exspected_status", (
        (0, cd.OK_RC),
        (1, cd.WARNING_RC),
        (3, cd.CRITICAL_RC),
))
def test_restarts(check_docker, monkeypatch, restarts, exspected_status):
    container_info = {'RestartCount': restarts, 'State': {'Running': True}}

    def mock_info_response(*args, **kwargs):
        return container_info

    monkeypatch.setattr(check_docker, 'get_container_info', value=mock_info_response)

    check_docker.check_restarts(container='container', warn=1, crit=2)
    assert check_docker.rc == exspected_status


@pytest.mark.parametrize("uptime, warn, crit, exspected_status", (
        (timedelta(seconds=0), 10, 5, cd.CRITICAL_RC),
        (timedelta(seconds=9), 10, 1, cd.WARNING_RC),
        (timedelta(seconds=10), 2, 1, cd.OK_RC),
        (timedelta(days=1, seconds=0), 2, 1, cd.OK_RC)
))
def test_check_uptime1(monkeypatch, check_docker, uptime, warn, crit, exspected_status):
    time = datetime.now(tz=timezone.utc) - uptime
    time_str = time.strftime("%Y-%m-%dT%H:%M:%S.0000000000Z")
    json_results = {
        'State': {'StartedAt': time_str,
                  'Running': True},
    }

    def mock_response(*args, **kwargs):
        encoded = json.dumps(obj=json_results).encode('utf-8')
        return FakeHttpResponse(encoded, 200)

    monkeypatch.setattr(check_docker.better_urllib_get, 'open', value=mock_response)

    check_docker.check_uptime(container='container', warn=warn, crit=crit)
    assert check_docker.rc == exspected_status


@pytest.fixture
def sample_containers_json():
    return [
        {'Names': ['/thing1']},
        {'Names': ['/thing2']}
    ]


def test_args_help(check_docker, capsys):
    args = tuple()
    check_docker.process_args(args=args)
    out, err = capsys.readouterr()
    assert 'usage: ' in out


def test_args_restart(check_docker):
    args = ('--restarts', 'non-default')
    result = check_docker.process_args(args=args)
    assert result.restarts == 'non-default'


def test_args_status(check_docker):
    args = ('--status', 'non-default')
    result = check_docker.process_args(args=args)
    assert result.status == 'non-default'


def test_args_memory(check_docker):
    args = ('--memory', 'non-default')
    result = check_docker.process_args(args=args)
    assert result.memory, 'non-default'


def test_args_containers(check_docker):
    args = ('--containers', 'non-default')
    result = check_docker.process_args(args=args)
    assert result.containers == ['non-default']


def test_args_containers_blank(check_docker):
    args = ('--containers',)
    with pytest.raises(SystemExit):
        check_docker.process_args(args=args)


def test_args_present(check_docker):
    result = check_docker.process_args(args=())
    assert not result.present
    args = ('--present',)
    result = check_docker.process_args(args=args)
    assert result.present


def test_args_timeout(check_docker):
    args = ('--timeout', '9999')
    result = check_docker.process_args(args=args)
    assert result.timeout == 9999.0


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


@pytest.mark.parametrize('arg, one_kb', (
        ('--binary_units', 1024),
        ('--decimal_units', 1000)
))
def test_units_base(check_docker, fs, arg, one_kb):
    # Assert value is driven by argprase results
    assert check_docker.unit_adjustments is None, "unit_adjustments has no sensible default wihout knowing the base"

    # Confirm default value is set
    parsed_args = check_docker.process_args([])
    assert parsed_args.units_base == 1024, "units_base should default to 1024"

    # Confirm value is updated by argparse flags
    parsed_args = check_docker.process_args([arg])
    assert parsed_args.units_base == one_kb, "units_base should be influenced by units flags"

    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.get_containers', return_value=['container1']), \
         patch('check_docker.get_stats',
               return_value={'memory_stats': {'limit': one_kb, 'usage': one_kb, 'stats': {'total_cache': 0}}}), \
         patch('check_docker.get_state', return_value={'Running': True}):
        check_docker.perform_checks(['--memory', '0:0:KB', arg])

    # Confirm unit adjustment table was updated by argument
    assert check_docker.unit_adjustments['KB'] == one_kb

    # Confirm output shows unit conversion specified by arg
    assert check_docker.performance_data == ['container1_mem=1.0KB;0;0;0;1.0']


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


def test_get_containers_1(check_docker, sample_containers_json):
    with patch('check_docker.get_url', return_value=(sample_containers_json, 200)):
        container_list = check_docker.get_containers('all', False)
        assert container_list == {'thing1', 'thing2'}


def test_get_containers_2(check_docker, sample_containers_json):
    with patch('check_docker.get_url', return_value=(sample_containers_json, 200)):
        container_list = check_docker.get_containers(['thing.*'], False)
        assert container_list == {'thing1', 'thing2'}


def test_get_containers_3(check_docker, sample_containers_json):
    check_docker.rc = -1
    with patch('check_docker.get_url', return_value=(sample_containers_json, 200)):
        with patch('check_docker.unknown') as patched:
            container_list = check_docker.get_containers({'foo'}, False)
            assert container_list == set()
            assert patched.call_count == 0


def test_get_containers_4(check_docker, sample_containers_json):
    check_docker.rc = -1
    with patch('check_docker.get_url', return_value=(sample_containers_json, 200)):
        with patch('check_docker.critical') as patched:
            container_list = check_docker.get_containers({'foo'}, True)
            assert container_list == set()
            assert patched.call_count == 1


def test_socketfile_failure_false(check_docker, fs):
    fs.CreateFile('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ('--status', 'running', '--connection', '/tmp/socket')
    result = check_docker.process_args(args=args)
    assert not check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_filetype(check_docker, fs):
    fs.CreateFile('/tmp/not_socket', contents='testing')
    args = ('--status', 'running', '--connection', '/tmp/not_socket')
    result = check_docker.process_args(args=args)
    assert check_docker.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_missing(check_docker, fs):
    args = ('--status', 'running', '--connection', '/tmp/missing')
    result = check_docker.process_args(args=args)
    check_docker.socketfile_permissions_failure(parsed_args=result)


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
    with patch('check_docker.get_url', return_value=([], 200)):
        with patch('check_docker.unknown') as patched:
            check_docker.perform_checks(args)
            assert patched.call_count == 1


@pytest.mark.parametrize("args, called", (
        (['--cpu', '0:0'], 'check_docker.check_cpu'),
        (['--memory', '0:0'], 'check_docker.check_memory'),
        (['--health'], 'check_docker.check_health'),
        (['--restarts', '1:1'], 'check_docker.check_restarts'),
        (['--status', 'running'], 'check_docker.check_status'),
        (['--uptime', '0:0'], 'check_docker.check_uptime'),
        (['--version'], 'check_docker.check_version'),
        ([], 'check_docker.unknown')
))
def test_perform(check_docker, fs, args, called):
    fs.CreateFile(check_docker.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.get_url', return_value=([{'Names': ['/thing1']}, ], 200)):
        with patch(called) as patched:
            check_docker.perform_checks(args)
            assert patched.call_count == 1


@pytest.mark.parametrize("messages, perf_data, exspected", (
        ([], [], ''),
        (['TEST'], [], 'TEST'),
        (['FOO', 'BAR'], [], 'FOO; BAR'),
        (['FOO', 'BAR'], ['1;2;3;4;'], 'FOO; BAR|1;2;3;4;')
))
def test_print_results(check_docker, capsys, messages, perf_data, exspected):
    check_docker.messages = messages
    check_docker.performance_data = perf_data
    check_docker.print_results()
    out, err = capsys.readouterr()
    assert out.strip() == exspected


def test_package_present():
    req = request.Request("https://pypi.python.org/pypi?:action=doap&name=check_docker", method="HEAD")
    with request.urlopen(req) as resp:
        assert resp.getcode() == 200


def test_ensure_new_version():
    version = cd.__version__
    req = request.Request("https://pypi.python.org/pypi?:action=doap&name=check_docker&version={version}".
                          format(version=version), method="HEAD")

    try:
        with request.urlopen(req) as resp:
            http_code = resp.getcode()
    except HTTPError as e:
        http_code = e.code
    assert http_code == 404, "Version already exists"


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
    with patch('check_docker.get_url', return_value=({'token': 'test'}, 200)):
        www_authenticate_header = 'Bearer realm="https://example.com/token",service="example.com",scope="repository:test:pull"'
        token = check_docker.get_manifest_auth_token(www_authenticate_header)
        assert token == 'test'


def test_get_container_image_urls(check_docker):
    container_response = {'Image': 'test'}
    image_response = {'RepoTags': ['test']}
    with patch('check_docker.get_container_info', return_value=container_response), \
         patch('check_docker.get_image_info', return_value=image_response):
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
    with patch('check_docker.get_container_info', return_value=container_response), \
         patch('check_docker.get_image_info', return_value=image_response):
        digest = check_docker.get_container_digest('container')
        assert digest == expected_digest


def test_get_digest_from_registry_no_auth(check_docker):
    response = FakeHttpResponse(content=b"", http_code=200, headers={'Docker-Content-Digest': "test_token"})

    with patch('check_docker.head_url', return_value=response):
        digest = check_docker.get_digest_from_registry('https://example.com/v2/test/manifests/lastest')
        assert digest == "test_token"


@pytest.mark.parametrize('local_container_digest,registry_container_digest, image_urls, expected_rc', (
        ('AAAA', 'AAAA', ('example.com/foo',), cd.OK_RC),
        ('AAAA', 'BBBB', ('example.com/foo',), cd.CRITICAL_RC),
        (None, '', ('example.com/foo',), cd.UNKNOWN_RC),
        ('', None, ('example.com/foo',), cd.UNKNOWN_RC),
        ('AAAA', 'AAAA', ('example.com/foo', 'example.com/bar'), cd.UNKNOWN_RC),
        ('AAAA', 'AAAA', tuple(), cd.UNKNOWN_RC),
))
def test_check_version(check_docker, local_container_digest, registry_container_digest, image_urls, expected_rc):
    with patch('check_docker.get_container_digest', return_value=local_container_digest), \
         patch('check_docker.get_container_image_urls', return_value=image_urls), \
         patch('check_docker.get_digest_from_registry', return_value=registry_container_digest):
        check_docker.check_version('container', tuple())
        assert check_docker.rc == expected_rc
