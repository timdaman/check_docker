import argparse
import json
import sys
from io import BytesIO
import stat
from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from pyfakefs import fake_filesystem_unittest
from importlib.machinery import SourceFileLoader
from urllib import request

__author__ = 'tim'

# This is needed because `check_swarm` does not end a a .py so it won't be found by default1
check_swarm = SourceFileLoader('check_swarm', './check_swarm').load_module()


class FakeHttpResponse(BytesIO):
    def __init__(self, content, http_code):
        self.code = http_code
        super(FakeHttpResponse, self).__init__(content)


class TestUtil(unittest.TestCase):
    def setUp(self):
        check_swarm.rc = -1
        self.services = [{'Spec': {"Name": 'FOO'}},
                          {'Spec': {"Name": 'BAR'}}]

    def test_get_url(self):
        obj = {'foo': 'bar'}
        encoded = json.dumps(obj=obj).encode('utf-8')
        expected_response = FakeHttpResponse(content=encoded, http_code=200)
        with patch('check_swarm.better_urllib_get.open', return_value=expected_response):
            response, _ = check_swarm.get_url(url='/test')
            self.assertDictEqual(response, obj)

    def test_get_swarm_status(self):
        with patch('check_swarm.get_url', return_value=('', 999)):
            response = check_swarm.get_swarm_status()
            self.assertEqual(response, 999)

    def test_get_service_info(self):
        with patch('check_swarm.get_url', return_value=('FOO', 999)):
            response_data, response_status = check_swarm.get_service_info('FOO')
            self.assertEqual(response_data, 'FOO')
            self.assertEqual(response_status, 999)

    def test_get_services_not_swarm(self):
        with patch('check_swarm.get_url', return_value=('', 406)):
            check_swarm.get_services('FOO')
            self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)

    def test_get_services_error(self):
        with patch('check_swarm.get_url', return_value=('', 500)):
            check_swarm.get_services('FOO')
            self.assertEqual(check_swarm.rc, check_swarm.UNKNOWN_RC)

    def test_get_services_all(self):
        with patch('check_swarm.get_url', return_value=(self.services, 200)):
            result=check_swarm.get_services('all')
            self.assertEqual(len(result), len(self.services))

class TestReporting(unittest.TestCase):
    def setUp(self):
        check_swarm.rc = -1
        check_swarm.messages = []
        check_swarm.performance_data = []

    def test_ok(self):
        check_swarm.ok("OK test")
        self.assertEqual(check_swarm.rc, check_swarm.OK_RC)
        self.assertListEqual(check_swarm.messages, ['OK: OK test'])

    def test_warn(self):
        check_swarm.warning("WARN test")
        self.assertEqual(check_swarm.rc, check_swarm.WARNING_RC)
        self.assertListEqual(check_swarm.messages, ['WARNING: WARN test'])

    def test_crit(self):
        check_swarm.critical("CRIT test")
        self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)
        self.assertListEqual(check_swarm.messages, ['CRITICAL: CRIT test'])

    def test_unknown(self):
        check_swarm.unknown("UNKNOWN test")
        self.assertEqual(check_swarm.rc, check_swarm.UNKNOWN_RC)
        self.assertListEqual(check_swarm.messages, ['UNKNOWN: UNKNOWN test'])

    def test_set_rc(self):
        # Can I do a basic set
        check_swarm.set_rc(check_swarm.OK_RC)
        self.assertEqual(check_swarm.rc, check_swarm.OK_RC)

        # Does it prevent downgrades of rc
        check_swarm.set_rc(check_swarm.WARNING_RC)
        self.assertEqual(check_swarm.rc, check_swarm.WARNING_RC)
        check_swarm.set_rc(check_swarm.OK_RC)
        self.assertEqual(check_swarm.rc, check_swarm.WARNING_RC)

    def test_process_url_status_ok(self):
        check_swarm.process_url_status(200, ok_msg='ok_msg', critical_msg='critical_msg', unknown_msg='unknown_msg')
        self.assertEqual(check_swarm.rc, check_swarm.OK_RC)
        self.assertListEqual(check_swarm.messages , ['OK: ok_msg'])


    def test_process_url_status_critical(self):
        check_swarm.process_url_status(404, ok_msg='ok_msg', critical_msg='critical_msg', unknown_msg='unknown_msg')
        self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)
        self.assertListEqual(check_swarm.messages , ['CRITICAL: critical_msg'])


    def test_process_url_status_unknown(self):
        check_swarm.process_url_status(418, ok_msg='ok_msg', critical_msg='critical_msg', unknown_msg='unknown_msg')
        self.assertEqual(check_swarm.rc, check_swarm.UNKNOWN_RC)
        self.assertListEqual(check_swarm.messages , ['UNKNOWN: unknown_msg'])

class TestArgs(unittest.TestCase):
    def setUp(self):
        check_swarm.rc = -1

    def test_args_timeout(self):
        args = ('--timeout', '9999', "--service", "FOO")
        result = check_swarm.process_args(args=args)
        self.assertEqual(result.timeout, 9999.0)

    def test_args_connection(self):
        args = ('--connection', '/foo', "--service", "FOO")
        result = check_swarm.process_args(args=args)
        self.assertEqual(result.connection, '/foo')
        self.assertEqual(check_swarm.daemon, 'socket:///foo:')

        args = ('--connection', 'example.com/bar', "--service", "FOO")
        result = check_swarm.process_args(args=args)
        self.assertEqual(result.connection, 'example.com/bar')
        self.assertEqual(check_swarm.daemon, 'http://example.com/bar')

    def test_args_secure_connection(self):
        args = ('--secure-connection', 'non-default', "--service", "FOO")
        result = check_swarm.process_args(args=args)
        self.assertEqual(result.secure_connection, 'non-default')

        args = ('--secure-connection', 'example.com/bar', "--service", "FOO")
        result = check_swarm.process_args(args=args)
        self.assertEqual(result.secure_connection, 'example.com/bar')
        self.assertEqual(check_swarm.daemon, 'https://example.com/bar')

    def test_args_mixed_connection(self):
        args = ('--connection', 'non-default', '--secure-connection', 'non-default', "--service", "FOO")
        try:
            self.assertRaises(argparse.ArgumentError, check_swarm.process_args, args)
        except SystemExit:  # Argument failures exit as well
            pass

    def test_args_mixed_checks(self):
        args = ('--swarm', "--service", "FOO")
        try:
            self.assertRaises(argparse.ArgumentError, check_swarm.process_args, args)
        except SystemExit:  # Argument failures exit as well
            pass

    def test_missing_check(self):
        args = tuple()
        with self.assertRaises(SystemExit):
            check_swarm.process_args(args=args)
            self.assertTrue(': error: one of the arguments' in sys.stderr.getvalue())


class TestSocket(fake_filesystem_unittest.TestCase):
    def setUp(self):
        check_swarm.rc = -1
        check_swarm.messages = []
        check_swarm.performance_data = []
        self.setUpPyfakefs()

    def test_socketfile_failure_false(self):
        self.fs.CreateFile('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
        args = ('--swarm', '--connection', '/tmp/socket')
        result = check_swarm.process_args(args=args)
        self.assertFalse(check_swarm.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_filetype(self):
        self.fs.CreateFile('/tmp/not_socket', contents='testing')
        args = ('--swarm', '--connection', '/tmp/not_socket')
        result = check_swarm.process_args(args=args)
        self.assertTrue(check_swarm.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_missing(self):
        args = ('--swarm', '--connection', '/tmp/missing')
        result = check_swarm.process_args(args=args)
        self.assertTrue(check_swarm.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_unwriteable(self):
        self.fs.CreateFile('/tmp/unwritable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--swarm', '--connection', '/tmp/unwritable')
        result = check_swarm.process_args(args=args)
        self.assertTrue(check_swarm.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_unreadable(self):
        self.fs.CreateFile('/tmp/unreadable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--swarm', '--connection', '/tmp/unreadable')
        result = check_swarm.process_args(args=args)
        self.assertTrue(check_swarm.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_http(self):
        self.fs.CreateFile('/tmp/http', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--swarm', '--connection', 'http://127.0.0.1')
        result = check_swarm.process_args(args=args)
        self.assertFalse(check_swarm.socketfile_permissions_failure(parsed_args=result))


class TestPerform(fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.setUpPyfakefs()
        self.fs.CreateFile(check_swarm.DEFAULT_SOCKET, contents='', st_mode=(stat.S_IFSOCK | 0o666))
        self.services = [{'Spec': {"Name": 'FOO'}},
                          {'Spec': {"Name": 'BAR'}}]
        self.service = {'Spec': {"Name": 'FOO'}}

        self.http_success_with_empty_payload = ('{}', 200)
        check_swarm.rc = -1

    def test_check_swarm_called(self):
        args = ['--swarm']
        with patch('check_swarm.get_url', return_value=(self.services, 200)):
            with patch('check_swarm.check_swarm') as patched:
                check_swarm.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_swarm_results_OK(self):
        args = ['--swarm']
        with patch('check_swarm.get_swarm_status', return_value=200):
                check_swarm.perform_checks(args)
                self.assertEqual(check_swarm.rc, check_swarm.OK_RC)

    def test_check_swarm_results_CRITICAL(self):
        args = ['--swarm']
        with patch('check_swarm.get_swarm_status', return_value=406):
                check_swarm.perform_checks(args)
                self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)

    def test_check_service_called(self):
        args = ['--service', 'FOO']
        with patch('check_swarm.get_url', return_value=(self.services, 200)):
            with patch('check_swarm.check_service') as patched:
                check_swarm.perform_checks(args)
                self.assertEqual(patched.call_count, 1)
                
    def test_check_service_results_OK(self):
        args = ['--service', 'FOO']
        with patch('check_swarm.get_services', return_value=['FOO','BAR']):
            with patch('check_swarm.get_service_info', return_value=(self.service, 200)):
                    check_swarm.perform_checks(args)
                    self.assertEqual(check_swarm.rc, check_swarm.OK_RC)

    def test_check_service_results_FAIL_missing(self):
        args = ['--service', 'missing1']
        with patch('check_swarm.get_url', return_value=(self.services, 200)):
                check_swarm.perform_checks(args)
                self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)

    def test_check_service_results_FAIL_unknown(self):
        args = ['--service', 'FOO']
        with patch('check_swarm.get_services', return_value=['FOO','BAR']):
            with patch('check_swarm.get_service_info', return_value=('', 500)):
                check_swarm.perform_checks(args)
                self.assertEqual(check_swarm.rc, check_swarm.UNKNOWN_RC)

    def test_check_no_services(self):
        args = ['--service', 'missing2']
        with patch('check_swarm.get_url', return_value=([], 200)):
            check_swarm.perform_checks(args)
            self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)

    def test_check_missing_service(self):
        args = ['--service', 'missing3']
        with patch('check_swarm.get_url', return_value=(self.services, 200)):
            check_swarm.perform_checks(args)
            self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)

    def test_check_not_swarm_service(self):
        args = ['--service', 'missing4']
        with patch('check_swarm.get_url', return_value=('', 406)):
            check_swarm.perform_checks(args)
            self.assertEqual(check_swarm.rc, check_swarm.CRITICAL_RC)


class TestOutput(unittest.TestCase):
    def setUp(self):
        check_swarm.messages = []
        check_swarm.performance_data = []

    check_swarm.messages = []

    def test_print_results1(self):
        check_swarm.messages = []
        check_swarm.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, '')

    def test_print_results2(self):
        check_swarm.messages = ['TEST']
        check_swarm.print_results()
        output = sys.stdout.getvalue().strip()

    def test_print_results3(self):
        check_swarm.messages = ['FOO', 'BAR']
        check_swarm.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, 'FOO; BAR')

    def test_print_results4(self):
        check_swarm.messages = ['FOO', 'BAR']

        check_swarm.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, 'FOO; BAR')


class TestVersion(unittest.TestCase):
    def test_package_present(self):
        req = request.Request("https://pypi.python.org/pypi?:action=doap&name=check_docker", method="HEAD")
        with request.urlopen(req) as resp:
            self.assertEqual(resp.getcode(), 200)

    def test_ensure_new_version(self):
        version = check_swarm.__version__
        req = request.Request("https://pypi.python.org/pypi?:action=doap&name=check_docker&version={version}".
                              format(version=version), method="HEAD")

        try:
            with request.urlopen(req) as resp:
                http_code = resp.getcode()
        except HTTPError as e:
            http_code = e.code
        self.assertEqual(http_code, 404, "Version already exists")


if __name__ == '__main__':
    unittest.main(buffer=True)
