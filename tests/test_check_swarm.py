import argparse
import json
import stat
from io import BytesIO
from unittest.mock import patch, call

import pytest

from check_docker import check_swarm as cs

__author__ = 'tim'


@pytest.fixture
def check_swarm():
    # This is needed because `check_docker` does not end a a .py so it won't be found by default
    from check_docker import check_swarm
    check_swarm.rc = -1
    check_swarm.timeout = 1
    check_swarm.messages = []
    check_swarm.performance_data = []
    check_swarm.daemon = 'socket:///notreal'
    check_swarm.get_url.cache_clear()
    return check_swarm


@pytest.fixture
def active_node():
    return {"ID": 44, 'Spec': {'Availability': 'active'}}


@pytest.fixture
def paused_node():
    return {"ID": 43, 'Spec': {'Availability': 'paused'}}


@pytest.fixture
def drain_node():
    return {"ID": 42, 'Spec': {'Availability': 'drain'}}


@pytest.fixture
def node_list(active_node, paused_node, drain_node):
    return active_node, paused_node, drain_node


active_node_task = {"NodeID": 44, 'Status': {'State': 'running'}}

paused_node_task = {"NodeID": 43, 'Status': {'State': 'running'}}

drain_node_task = {"NodeID": 42, 'Status': {'State': 'running'}}


class FakeHttpResponse(BytesIO):
    def __init__(self, content, http_code):
        self.status = http_code
        super(FakeHttpResponse, self).__init__(content)


def test_get_url(check_swarm, monkeypatch):
    obj = {'foo': 'bar'}
    encoded = json.dumps(obj=obj).encode('utf-8')
    expected_response = FakeHttpResponse(content=encoded, http_code=200)

    def mock_open(*args, **kwargs):
        return expected_response

    monkeypatch.setattr(check_swarm.better_urllib_get, 'open', value=mock_open)
    response, _ = check_swarm.get_url(url='/test')
    assert response == obj


def test_get_swarm_status(check_swarm):
    with patch('check_docker.check_swarm.get_url', return_value=('', 999)):
        response, status = check_swarm.get_swarm_status()
        assert status == 999


def test_get_service_info(check_swarm):
    sample_response = ([{'Status': {'State': 'running', 'DesiredState': 'running'}},
                        {'Status': {'State': 'failed', 'DesiredState': 'running'}}], 999)
    with patch('check_docker.check_swarm.get_url', return_value=sample_response):
        response_data = check_swarm.get_service_tasks('FOO')
        assert len(response_data) == 2


def test_get_services_not_swarm(check_swarm):
    with patch('check_docker.check_swarm.get_url', return_value=('', 406)):
        check_swarm.get_services('FOO')
        assert check_swarm.rc == check_swarm.CRITICAL_RC


def test_get_services_error(check_swarm):
    with patch('check_docker.check_swarm.get_url', return_value=('', 500)):
        check_swarm.get_services('FOO')
        assert check_swarm.rc == check_swarm.UNKNOWN_RC


def test_get_services_all(check_swarm):
    services = [{'Spec': {"Name": 'FOO'}},
                {'Spec': {"Name": 'BAR'}}]
    with patch('check_docker.check_swarm.get_url', return_value=(services, 200)):
        result = check_swarm.get_services('all')
        assert len(result) == len(services)


@pytest.mark.parametrize('func,arg,rc,messages',
                         (
                                 ('ok', "OK test", cs.OK_RC, ['OK: OK test']),
                                 ('warning', "WARN test", cs.WARNING_RC, ['WARNING: WARN test']),
                                 ('critical', "CRIT test", cs.CRITICAL_RC, ['CRITICAL: CRIT test']),
                                 ('unknown', "UNKNOWN test", cs.UNKNOWN_RC, ['UNKNOWN: UNKNOWN test']),
                         ))
def test_status_update(check_swarm, func, arg, rc, messages):
    getattr(check_swarm, func)(arg)
    assert check_swarm.rc == rc
    assert check_swarm.messages == messages


def test_set_rc(check_swarm):
    # Can I do a basic set
    check_swarm.set_rc(check_swarm.OK_RC)
    assert check_swarm.rc == check_swarm.OK_RC

    # Does it prevent downgrades of rc
    check_swarm.set_rc(check_swarm.WARNING_RC)
    assert check_swarm.rc == check_swarm.WARNING_RC
    check_swarm.set_rc(check_swarm.OK_RC)
    assert check_swarm.rc == check_swarm.WARNING_RC


@pytest.mark.parametrize('code, expected_rc, expected_messages', (
        (200, cs.OK_RC, ['OK: ok_msg']),
        (404, cs.CRITICAL_RC, ['CRITICAL: critical_msg']),
        (418, cs.UNKNOWN_RC, ['UNKNOWN: unknown_msg']),
))
def test_process_url_status_ok(check_swarm, code, expected_rc, expected_messages):
    check_swarm.process_url_status(code, ok_msg='ok_msg', critical_msg='critical_msg', unknown_msg='unknown_msg')
    assert check_swarm.rc == expected_rc
    assert check_swarm.messages == expected_messages


def test_args_timeout(check_swarm):
    args = ('--timeout', '9999', '--swarm')
    result = check_swarm.process_args(args=args)
    assert result.timeout == 9999.0


def test_args_connection(check_swarm):
    args = ('--connection', '/foo', '--swarm')
    result = check_swarm.process_args(args=args)
    assert result.connection == '/foo'
    assert check_swarm.daemon == 'socket:///foo:'

    args = ('--connection', 'foo.com/bar', '--swarm')
    result = check_swarm.process_args(args=args)
    assert result.connection == 'foo.com/bar'
    assert check_swarm.daemon == 'http://foo.com/bar'


def test_args_secure_connection(check_swarm):
    args = ('--secure-connection', 'non-default', '--swarm')
    result = check_swarm.process_args(args=args)
    assert result.secure_connection == 'non-default'

    args = ('--secure-connection', 'foo.com/bar', '--swarm')
    result = check_swarm.process_args(args=args)
    assert result.secure_connection == 'foo.com/bar'
    assert check_swarm.daemon == 'https://foo.com/bar'


def test_args_mixed_connection(check_swarm):
    args = ('--connection', 'non-default', '--secure-connection', 'non-default', '--swarm')
    with pytest.raises(SystemExit):
        check_swarm.process_args(args)


def test_missing_check(check_swarm):
    try:
        with pytest.raises(argparse.ArgumentError):
            check_swarm.process_args(tuple())
    except SystemExit:  # Argument failures exit as well
        pass


def test_args_mixed_checks(check_swarm):
    try:
        with pytest.raises(argparse.ArgumentError):
            check_swarm.process_args(['--swarm', "--service", "FOO"])
    except SystemExit:  # Argument failures exit as well
        pass


def test_socketfile_failure_false(check_swarm, fs):
    fs.create_file('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ('--swarm', '--connection', '/tmp/socket')
    result = check_swarm.process_args(args=args)
    assert not check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_filetype(check_swarm, fs):
    fs.create_file('/tmp/not_socket', contents='testing')
    args = ('--swarm', '--connection', '/tmp/not_socket')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_missing(check_swarm, fs):
    args = ('--swarm', '--connection', '/tmp/missing')
    result = check_swarm.process_args(args=args)
    check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unwriteable(check_swarm, fs):
    fs.create_file('/tmp/unwritable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', '/tmp/unwritable')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unreadable(check_swarm, fs):
    fs.create_file('/tmp/unreadable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', '/tmp/unreadable')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_http(check_swarm, fs):
    fs.create_file('/tmp/http', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', 'http://127.0.0.1')
    result = check_swarm.process_args(args=args)
    assert not check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_check_swarm_called(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.check_swarm') as patched:
        check_swarm.perform_checks(args)
        assert patched.call_count == 1


def test_check_swarm_results_OK(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=({'Swarm': {'LocalNodeState': 'active'}}, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.OK_RC


def test_check_swarm_results_CRITICAL(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=({'Swarm': {'LocalNodeState': 'inactive'}}, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_swarm_results_WARNING(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=({'Swarm': {'LocalNodeState': 'pending'}}, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.WARNING_RC


def test_check_swarm_results_UNKNOWN(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=({}, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.UNKNOWN_RC


def test_check_service_called(check_swarm, fs):
    service_info = {'Spec': {'Mode': {'Replicated': {'Replicas': 1}}}}

    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'FOO']
    with patch('check_docker.check_swarm.get_services', return_value=[service_info]):
        with patch('check_docker.check_swarm.check_service') as patched:
            check_swarm.perform_checks(args)
            assert patched.call_count == 1


@pytest.mark.parametrize("service_info, expected_func, expected_args", (
        ({'Spec': {'Mode': {'Global': {}}}}, 'process_global_service', {'name': 'FOO', 'ignore_paused': False}),
        ({'Spec': {'Mode': {'Replicated': {'Replicas': 1}}}}, 'process_replicated_service',
         {'name': 'FOO', 'replicas_desired': 1}),
        ({'Spec': {'Mode': {'Replicated': {'Replicas': 3}}}}, 'process_replicated_service',
         {'name': 'FOO', 'replicas_desired': 3}),
))
def test_check_services_routing_global(check_swarm, service_info, expected_func, expected_args, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_swarm.get_service_info', return_value=(service_info, 999)), \
         patch('check_docker.check_swarm.{}'.format(expected_func)) as patched:
        check_swarm.check_service('FOO')
        assert patched.call_count == 1
        assert patched.call_args == call(**expected_args)


def test_check_services_global_ignore_paused(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    service_info = {'Spec': {'Mode': {'Global': {}}}}

    with patch('check_docker.check_swarm.get_service_info', return_value=(service_info, 999)), \
         patch('check_docker.check_swarm.process_global_service') as patched:
        check_swarm.check_service('FOO', True)
        assert patched.call_count == 1
        assert patched.call_args == call(name='FOO', ignore_paused=True)


@pytest.mark.parametrize("service_list, ignore_paused, expected_rc", (
        ([active_node_task, paused_node_task, drain_node_task], False, cs.OK_RC),
        ([active_node_task, drain_node_task], False, cs.CRITICAL_RC),
        ([active_node_task, paused_node_task], False, cs.OK_RC),
        ([active_node_task], False, cs.CRITICAL_RC),
        ([paused_node_task], False, cs.CRITICAL_RC),
        ([], False, cs.CRITICAL_RC),
        ([active_node_task], True, cs.OK_RC),
        ([paused_node_task], True, cs.CRITICAL_RC),
))
def test_process_global_service(check_swarm, fs, node_list, service_list, ignore_paused, expected_rc):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_swarm.get_nodes', return_value=(node_list, 999)) as patched_get_nodes, \
            patch('check_docker.check_swarm.get_service_tasks', return_value=service_list) as patched_get_service_tasks:
        check_swarm.process_global_service('FOO', ignore_paused)
        assert patched_get_nodes.call_count == 1
        assert patched_get_service_tasks.call_count == 1
        assert check_swarm.rc == expected_rc


@pytest.mark.parametrize("service_list, expected_rc", (
        ([active_node_task, paused_node_task, drain_node_task], cs.CRITICAL_RC),
        ([active_node_task, paused_node_task], cs.OK_RC),
        ([active_node_task], cs.CRITICAL_RC),
        ([], cs.CRITICAL_RC),
))
def test_process_replicated_service(check_swarm, fs, service_list, expected_rc):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    with patch('check_docker.check_swarm.get_service_tasks',
               return_value=service_list) as patched_get_service_running_tasks:
        check_swarm.process_replicated_service('FOO', 2)
        assert patched_get_service_running_tasks.call_count == 1
        assert check_swarm.rc == expected_rc


def test_check_service_results_FAIL_missing(check_swarm, fs):
    service_info = {'Spec': {'Name': 'FOO', 'Mode': {'Global': {}}}}
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing1']
    with patch('check_docker.check_swarm.get_url', return_value=([service_info], 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_service_results_FAIL_unknown(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'FOO']
    with patch('check_docker.check_swarm.get_services', return_value=['FOO', 'BAR']):
        with patch('check_docker.check_swarm.get_service_info', return_value=('', 500)):
            check_swarm.perform_checks(args)
            assert check_swarm.rc == cs.UNKNOWN_RC


def test_check_no_services(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing2']
    with patch('check_docker.check_swarm.get_url', return_value=([], 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_missing_service(check_swarm, fs):
    service_info = {'Spec': {'Name': 'FOO', 'Mode': {'Global': {}}}}
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing3']
    with patch('check_docker.check_swarm.get_url', return_value=([service_info], 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_not_swarm_service(check_swarm, fs):
    fs.create_file(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing4']
    with patch('check_docker.check_swarm.get_url', return_value=('', 406)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


@pytest.mark.parametrize("messages, perf_data, expected", (
        ([], [], ''),
        (['TEST'], [], 'TEST'),
        (['FOO', 'BAR'], [], 'FOO\nBAR'),
))
def test_print_results(check_swarm, capsys, messages, perf_data, expected):
    check_swarm.messages = messages
    check_swarm.performance_data = perf_data
    check_swarm.print_results()
    out, err = capsys.readouterr()
    assert out.strip() == expected
