import argparse
import json
import stat
from io import BytesIO
from unittest.mock import patch

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
        response = check_swarm.get_swarm_status()
        assert response == 999


def test_get_service_info(check_swarm):
    with patch('check_docker.check_swarm.get_url', return_value=('FOO', 999)):
        response_data, response_status = check_swarm.get_service_info('FOO')
        assert response_data == 'FOO'
        assert response_status == 999


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
    fs.CreateFile('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ('--swarm', '--connection', '/tmp/socket')
    result = check_swarm.process_args(args=args)
    assert not check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_filetype(check_swarm, fs):
    fs.CreateFile('/tmp/not_socket', contents='testing')
    args = ('--swarm', '--connection', '/tmp/not_socket')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_missing(check_swarm, fs):
    args = ('--swarm', '--connection', '/tmp/missing')
    result = check_swarm.process_args(args=args)
    check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unwriteable(check_swarm, fs):
    fs.CreateFile('/tmp/unwritable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', '/tmp/unwritable')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_unreadable(check_swarm, fs):
    fs.CreateFile('/tmp/unreadable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', '/tmp/unreadable')
    result = check_swarm.process_args(args=args)
    assert check_swarm.socketfile_permissions_failure(parsed_args=result)


def test_socketfile_failure_http(check_swarm, fs):
    fs.CreateFile('/tmp/http', contents='', st_mode=(stat.S_IFSOCK | 0o000))
    args = ('--swarm', '--connection', 'http://127.0.0.1')
    result = check_swarm.process_args(args=args)
    assert not check_swarm.socketfile_permissions_failure(parsed_args=result)


@pytest.fixture()
def services():
    return [{'Spec': {"Name": 'FOO'}}, {'Spec': {"Name": 'BAR'}}]


def test_check_swarm_called(check_swarm, fs, services):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_url', return_value=(services, 200)):
        with patch('check_docker.check_swarm.check_swarm') as patched:
            check_swarm.perform_checks(args)
            assert patched.call_count == 1


def test_check_swarm_results_OK(check_swarm, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=200):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.OK_RC


def test_check_swarm_results_CRITICAL(check_swarm, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--swarm']
    with patch('check_docker.check_swarm.get_swarm_status', return_value=406):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_service_called(check_swarm, services, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'FOO']
    with patch('check_docker.check_swarm.get_url', return_value=(services, 200)):
        with patch('check_docker.check_swarm.check_service') as patched:
            check_swarm.perform_checks(args)
            assert patched.call_count == 1


def test_check_service_results_OK(check_swarm, services, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'FOO']
    with patch('check_docker.check_swarm.get_services', return_value=['FOO', 'BAR']):
        with patch('check_docker.check_swarm.get_service_info', return_value=(services, 200)):
            check_swarm.perform_checks(args)
            assert check_swarm.rc == cs.OK_RC


def test_check_service_results_FAIL_missing(check_swarm, services, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing1']
    with patch('check_docker.check_swarm.get_url', return_value=(services, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_service_results_FAIL_unknown(check_swarm, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'FOO']
    with patch('check_docker.check_swarm.get_services', return_value=['FOO', 'BAR']):
        with patch('check_docker.check_swarm.get_service_info', return_value=('', 500)):
            check_swarm.perform_checks(args)
            assert check_swarm.rc == cs.UNKNOWN_RC


def test_check_no_services(check_swarm, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing2']
    with patch('check_docker.check_swarm.get_url', return_value=([], 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_missing_service(check_swarm, services, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing3']
    with patch('check_docker.check_swarm.get_url', return_value=(services, 200)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


def test_check_not_swarm_service(check_swarm, fs):
    fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
    args = ['--service', 'missing4']
    with patch('check_docker.check_swarm.get_url', return_value=('', 406)):
        check_swarm.perform_checks(args)
        assert check_swarm.rc == cs.CRITICAL_RC


@pytest.mark.parametrize("messages, perf_data, expected", (
        ([], [], ''),
        (['TEST'], [], 'TEST'),
        (['FOO', 'BAR'], [], 'FOO; BAR'),
))
def test_print_results(check_swarm, capsys, messages, perf_data, expected):
    check_swarm.messages = messages
    check_swarm.performance_data = perf_data
    check_swarm.print_results()
    out, err = capsys.readouterr()
    assert out.strip() == expected
