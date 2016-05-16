import argparse

__author__ = 'tim'

import unittest
from unittest.mock import patch
from argparse import ArgumentError
import check_docker


class TestCheckDocker(unittest.TestCase):
    def setUp(self):
        check_docker.rc = -1
        check_docker.messages = []
        check_docker.performance_data = []
        check_docker.daemon = 'socket:///var/run/docker.sock'

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

    def test_parse_thresholds(self):
        a = check_docker.parse_thresholds('1:2:3')
        self.assertTupleEqual(a, (1, 2, '3'))

        a = check_docker.parse_thresholds('1:2')
        self.assertTupleEqual(a, (1, 2, None))

        self.assertRaises(ValueError, check_docker.parse_thresholds, "a:1:c")

        self.assertRaises(ValueError, check_docker.parse_thresholds, "1:b:c")

        self.assertRaises(IndexError, check_docker.parse_thresholds, "1")

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

    def test_get_containers(self):
        json_results = [
            {'Names': ['/thing1']},
            {'Names': ['/thing2']}
        ]
        with patch('check_docker.get_url', return_value=json_results):
            container_list = check_docker.get_containers('all')
            self.assertListEqual(container_list, ['thing1', 'thing2'])

        with patch('check_docker.get_url', return_value=json_results):
            container_list = check_docker.get_containers(['foo'])
            self.assertListEqual(container_list, ['foo'])

if __name__ == '__main__':
    unittest.main()
