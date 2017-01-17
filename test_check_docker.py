import argparse
import os
import stat
from datetime import datetime, timezone, timedelta

from pyfakefs import fake_filesystem_unittest

__author__ = 'tim'

import unittest
from unittest.mock import patch
from argparse import ArgumentError
import check_docker


class TestCheckDocker(fake_filesystem_unittest.TestCase):
    def setUp(self):
        check_docker.rc = -1
        check_docker.messages = []
        check_docker.performance_data = []
        check_docker.daemon = 'socket://' + check_docker.DEFAULT_SOCKET
        self.setUpPyfakefs()

    def test_evaluate_numeric_thresholds_ok(self):
        # Test OK
        check_docker.evaluate_numeric_thresholds(container='container',
                                                 value=1,
                                                 warn=2,
                                                 crit=3,
                                                 name='metric',
                                                 short_name='met',
                                                 min=0,
                                                 max=10,
                                                 units='b'
                                                 )
        self.assertEqual(check_docker.rc, check_docker.OK_RC, "Incorrect return code")
        self.assertListEqual(check_docker.messages, ['OK: container metric is 1b'])
        self.assertListEqual(check_docker.performance_data, ['container_met=1b;2;3;0;10'])

    def test_evaluate_numeric_thresholds_warn(self):
        # Test warn
        check_docker.evaluate_numeric_thresholds(container='container',
                                                 value=2,
                                                 warn=2,
                                                 crit=3,
                                                 name='metric',
                                                 short_name='met',
                                                 min=0,
                                                 max=10,
                                                 units='b'
                                                 )
        self.assertEqual(check_docker.rc, check_docker.WARNING_RC, "Incorrect return code")
        self.assertListEqual(check_docker.messages, ['WARNING: container metric is 2b'])
        self.assertListEqual(check_docker.performance_data, ['container_met=2b;2;3;0;10'])

    def test_evaluate_numeric_thresholds_crit(self):
        # Test crit
        check_docker.evaluate_numeric_thresholds(container='container',
                                                 value=3,
                                                 warn=2,
                                                 crit=3,
                                                 name='metric',
                                                 short_name='met',
                                                 min=0,
                                                 max=10,
                                                 units='b'
                                                 )
        self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC, "Incorrect return code")
        self.assertListEqual(check_docker.messages, ['CRITICAL: container metric is 3b'])
        self.assertListEqual(check_docker.performance_data, ['container_met=3b;2;3;0;10'])

    def test_ok(self):
        check_docker.ok("OK test")
        self.assertEqual(check_docker.rc, check_docker.OK_RC)
        self.assertListEqual(check_docker.messages, ['OK: OK test'])

    def test_warn(self):
        check_docker.warning("WARN test")
        self.assertEqual(check_docker.rc, check_docker.WARNING_RC)
        self.assertListEqual(check_docker.messages, ['WARNING: WARN test'])

    def test_crit(self):
        check_docker.critical("CRIT test")
        self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)
        self.assertListEqual(check_docker.messages, ['CRITICAL: CRIT test'])

    def test_unknown(self):
        check_docker.unknown("UNKNOWN test")
        self.assertEqual(check_docker.rc, check_docker.UNKNOWN_RC)
        self.assertListEqual(check_docker.messages, ['UNKNOWN: UNKNOWN test'])

    def test_parse_thresholds_with_units(self):
        a = check_docker.parse_thresholds('1:2:3')
        self.assertTupleEqual(tuple(a), (1, 2, '3'))

    def test_parse_thresholds_with_missing_units(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, '1:2')

    def test_parse_thresholds_with_units_when_disabled(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, '1:2:b', include_units=False)

    def test_parse_thresholds_missing_units_when_optional(self):
        a = check_docker.parse_thresholds('1:2', units_required=False)
        self.assertTupleEqual(tuple(a), (1, 2, None))

    def test_parse_thresholds_with_units_when_optional(self):
        a = check_docker.parse_thresholds('1:2:3', units_required=False)
        self.assertTupleEqual(tuple(a), (1, 2, '3'))

    def test_parse_thresholds_missing_units_when_not_optional(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, '1:2', units_required=True)

    def test_parse_thresholds_with_units_when_not_optional(self):
        a = check_docker.parse_thresholds('1:2:3', units_required=True)
        self.assertTupleEqual(tuple(a), (1, 2, '3'))

    def test_parse_thresholds_missing_crit(self):
        self.assertRaises(IndexError, check_docker.parse_thresholds, "1")

    def test_parse_thresholds_blank_warn(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, ":1")
        self.assertRaises(ValueError, check_docker.parse_thresholds, ":1:c")

    def test_parse_thresholds_blank_crit(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, "1:")
        self.assertRaises(ValueError, check_docker.parse_thresholds, "1::c")

    def test_parse_thresholds_blank_units(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, '1:2:', units_required=True)

    def test_parse_thresholds_str_warn(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, "a:1:c")

    def test_parse_thresholds_str_crit(self):
        self.assertRaises(ValueError, check_docker.parse_thresholds, "1:b:c")

    def test_set_rc(self):
        # Can I do a basic set
        check_docker.set_rc(check_docker.OK_RC)
        self.assertEqual(check_docker.rc, check_docker.OK_RC)

        # Does it prevent downgrades of rc
        check_docker.set_rc(check_docker.WARNING_RC)
        self.assertEqual(check_docker.rc, check_docker.WARNING_RC)
        check_docker.set_rc(check_docker.OK_RC)
        self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_status1(self):
        json_results = {
            'State': {'Status': 'running'},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_status(container='container', desired_state='running')
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_status2(self):
        json_results = {
            'State': {'Status': 'stopped'},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_status(container='container', desired_state='running')
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_memory1(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 0
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=1, crit=2, units='b')
                self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_memory2(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 1
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=1, crit=2, units='b')
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_memory3(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 2
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=1, crit=2, units='b')
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_memory4(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 1
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=20, crit=30, units='%')
                self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_memory5(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 2
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=20, crit=30, units='%')
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_memory6(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 3
                             }
        }

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_memory(container='container', warn=20, crit=30, units='%')
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_restarts1(self):
        container_info = {'RestartCount': 0}

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_restarts(container='container', warn=1, crit=2)
                self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_restarts2(self):
        container_info = {'RestartCount': 1}

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_restarts(container='container', warn=1, crit=2)
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_restarts3(self):
        container_info = {'RestartCount': 3}

        with patch('check_docker.get_status', return_value='running'):
            with patch('check_docker.get_container_info', return_value=container_info):
                check_docker.check_restarts(container='container', warn=1, crit=2)
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_uptime1(self):
        now_string = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container_name='container', warn=10, crit=5)
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_uptime2(self):
        ten = timedelta(seconds=10)
        then = datetime.now(tz=timezone.utc) - ten
        now_string = then.strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container_name='container', warn=20, crit=1)
            self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_uptime3(self):
        ten = timedelta(seconds=10)
        then = datetime.now(tz=timezone.utc) - ten
        now_string = then.strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container_name='container', warn=2, crit=1)
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_args_restart(self):
        args = ('--restarts', 'non-default')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.restarts, 'non-default')

    def test_args_status(self):
        args = ('--status', 'non-default')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.status, 'non-default')

    def test_args_memory(self):
        args = ('--memory', 'non-default')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.memory, 'non-default')

    def test_args_containers(self):
        args = ('--containers', 'non-default')
        result = check_docker.process_args(args=args)
        self.assertListEqual(result.containers, ['non-default'])

    def test_args_containers_blank(self):
        args = ('--containers',)
        try:
            self.assertRaises(argparse.ArgumentError, check_docker.process_args, args=args)
        except SystemExit:  # Argument failures exit as well
            pass

    def test_args_timeout(self):
        args = ('--timeout', '9999')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.timeout, 9999.0)

    def test_args_connection(self):
        args = ('--connection', '/foo')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.connection, '/foo')
        self.assertEqual(check_docker.daemon, 'socket:///foo:')

        args = ('--connection', 'foo.com/bar')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.connection, 'foo.com/bar')
        self.assertEqual(check_docker.daemon, 'http://foo.com/bar')

    def test_args_secure_connection(self):
        args = ('--secure-connection', 'non-default')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.secure_connection, 'non-default')

        args = ('--secure-connection', 'foo.com/bar')
        result = check_docker.process_args(args=args)
        self.assertEqual(result.secure_connection, 'foo.com/bar')
        self.assertEqual(check_docker.daemon, 'https://foo.com/bar')

    def test_args_mixed_connection(self):
        args = ('--connection', 'non-default', '--secure-connection', 'non-default')
        try:
            self.assertRaises(argparse.ArgumentError, check_docker.process_args, args)
        except SystemExit:  # Argument failures exit as well
            pass

    def test_missing_check(self):
        args = tuple()
        result = check_docker.process_args(args=args)
        self.assertTrue(check_docker.no_checks_present(result))

    def test_present_check(self):
        args = ('--status', 'running')
        result = check_docker.process_args(args=args)
        self.assertFalse(check_docker.no_checks_present(result))

    def test_get_containers(self):
        json_results = [
            {'Names': ['/thing1']},
            {'Names': ['/thing2']}
        ]
        with patch('check_docker.get_url', return_value=json_results):
            container_list = check_docker.get_containers('all')
            self.assertListEqual(container_list, ['thing1', 'thing2'])

        with patch('check_docker.get_url', return_value=json_results):
            container_list = check_docker.get_containers(['thing.*'])
            self.assertListEqual(container_list, ['thing1', 'thing2'])

        with patch('check_docker.get_url', return_value=json_results):
            container_list = check_docker.get_containers(['foo'])
            self.assertListEqual(container_list, [])

    def test_socketfile_failure_false(self):
        self.fs.CreateFile('/tmp/socket', contents='', st_mode=(stat.S_IFSOCK | 0o666))
        args = ('--status', 'running', '--connection', '/tmp/socket')
        result = check_docker.process_args(args=args)
        self.assertFalse(check_docker.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_filetype(self):
        self.fs.CreateFile('/tmp/not_socket', contents='testing')
        args = ('--status', 'running', '--connection', '/tmp/not_socket')
        result = check_docker.process_args(args=args)
        self.assertTrue(check_docker.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_missing(self):
        args = ('--status', 'running', '--connection', '/tmp/missing')
        result = check_docker.process_args(args=args)
        self.assertTrue(check_docker.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_unwriteable(self):
        self.fs.CreateFile('/tmp/unwritable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--status', 'running', '--connection', '/tmp/unwritable')
        result = check_docker.process_args(args=args)
        self.assertTrue(check_docker.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_unreadable(self):
        self.fs.CreateFile('/tmp/unreadable', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--status', 'running', '--connection', '/tmp/unreadable')
        result = check_docker.process_args(args=args)
        self.assertTrue(check_docker.socketfile_permissions_failure(parsed_args=result))

    def test_socketfile_failure_http(self):
        self.fs.CreateFile('/tmp/http', contents='', st_mode=(stat.S_IFSOCK | 0o000))
        args = ('--status', 'running', '--connection', 'http://127.0.0.1')
        result = check_docker.process_args(args=args)
        self.assertFalse(check_docker.socketfile_permissions_failure(parsed_args=result))


if __name__ == '__main__':
    unittest.main()
