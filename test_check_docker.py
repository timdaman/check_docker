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


check_docker = SourceFileLoader('check_docker', './check_docker').load_module()


class TestUtil(unittest.TestCase):
    def test_get_url(self):
        obj = {'foo': 'bar'}
        encoded = json.dumps(obj=obj).encode('utf-8')
        results = BytesIO(encoded)
        with patch('check_docker.better_urllib_get.open', return_value=results):
            response = check_docker.get_url(url='/test')
            self.assertDictEqual(response, obj)

    def test_get_stats(self):
        with patch('check_docker.get_url', return_value=[]) as patched:
            check_docker.get_stats('container')
            self.assertEqual(patched.call_count, 1)

    def test_get_state(self):
        with patch('check_docker.get_url', return_value={'State': {}}) as patched:
            check_docker.get_state('container')
            self.assertEqual(patched.call_count, 1)

    def test_get_get_image_info(self):
        with patch('check_docker.get_url', return_value=[]) as patched:
            check_docker.get_image_info('container')
            self.assertEqual(patched.call_count, 1)


class TestReporting(unittest.TestCase):
    def setUp(self):
        check_docker.rc = -1
        check_docker.messages = []
        check_docker.performance_data = []

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


class TestChecks(fake_filesystem_unittest.TestCase):
    def setUp(self):
        check_docker.rc = -1
        check_docker.messages = []
        check_docker.performance_data = []
        check_docker.get_url.cache_clear()

    def test_check_status1(self):
        json_results = {
            'State': {'Running': True},
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

    # This how older docker engines display state
    def test_check_status3(self):
        json_results = {
            'State': {'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_status(container='container', desired_state='running')
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    # This how older docker engines display state
    def test_check_status4(self):
        json_results = {
            'State': {'Running': False},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_status(container='container', desired_state='running')
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    # This how older docker engines display state
    def test_check_status5(self):
        json_results = {
            'State': {'foo': False},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_status(container='container', desired_state='running')
            self.assertEqual(check_docker.rc, check_docker.UNKNOWN_RC)

    def test_check_health1(self):
        json_results = {
            'State': {'Health': {'Status': 'healthy'}, 'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_health(container='container')
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_health2(self):
        json_results = {
            'State': {'Health': {'Status': 'unhealthy'}, 'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_health(container='container')
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_health3(self):
        json_results = {
            'State': {'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_health(container='container')
            self.assertEqual(check_docker.rc, check_docker.UNKNOWN_RC)

    def test_check_health4(self):
        json_results = {
            'State': {'Health': {}, 'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_health(container='container')
            self.assertEqual(check_docker.rc, check_docker.UNKNOWN_RC)

    def test_check_health5(self):
        json_results = {
            'State': {'Health': {'Status': 'starting'}, 'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_health(container='container')
            self.assertEqual(check_docker.rc, check_docker.UNKNOWN_RC)

    def test_check_memory1(self):
        container_info = {
            'State': {'Running': True},
            'memory_stats': {'limit': 10,
                             'usage': 0
                             }
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=1, crit=2, units='b')
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_memory2(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 1
                             },
            'State': {'Running': True}
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=1, crit=2, units='b')
            self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_memory3(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 2
                             },
            'State': {'Running': True}
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=1, crit=2, units='b')
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_memory4(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 1
                             },
            'State': {'Running': True}
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=20, crit=30, units='%')
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_memory5(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 2
                             },
            'State': {'Running': True}
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=20, crit=30, units='%')
            self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_memory6(self):
        container_info = {
            'memory_stats': {'limit': 10,
                             'usage': 3
                             },
            'State': {'Running': True}
        }

        with patch('check_docker.get_url', return_value=container_info):
            check_docker.check_memory(container='container', warn=20, crit=30, units='%')
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_cpu1(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [15],
                                        'total_usage': 15},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }
        }

        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_calculate_cpu1(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [15],
                                        'total_usage': 15},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }
        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 5)

    def test_check_cpu2(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [25],
                                        'total_usage': 25},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }
        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 15)
        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_calculate_cpu2(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [25],
                                        'total_usage': 25},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }
        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 15)

    def test_check_cpu3(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }
        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_calculate_cpu3(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 1000000000,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 25)

    def test_check_cpu4(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [15],
                                        'total_usage': 15},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 10000,
            }

        }
        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_calculate_cpu4(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [15],
                                        'total_usage': 15},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 10000,
            }

        }
        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 50)

    def test_check_cpu5(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_calculate_cpu5(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'online_cpus': 1,
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 25)

    def test_check_cpu6(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 1,
                "CpuQuota": 2,
            }

        }

        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_calculate_cpu6(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35],
                                        'total_usage': 35},
                          'online_cpus': 1,
                          'system_cpu_usage': 100},
            'precpu_stats': {'cpu_usage': {'percpu_usage': [10],
                                           'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 1,
                "CpuQuota": 2,
            }

        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 25)

    def test_check_cpu7(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'total_usage': 36},
                          'online_cpus': 2,
                          'system_cpu_usage': 200},
            'precpu_stats': {'cpu_usage': {'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_calculate_cpu7(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'total_usage': 36},
                          'online_cpus': 2,
                          'system_cpu_usage': 200},
            'precpu_stats': {'cpu_usage': {'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 13)

    def test_check_cpu8(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35, 1],
                                        'total_usage': 36},
                          'system_cpu_usage': 200},
            'precpu_stats': {'cpu_usage': {'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        with patch('check_docker.get_container_info', return_value=container_info):
            with patch('check_docker.get_stats', return_value=container_stats):
                check_docker.check_cpu(container='container', warn=10, crit=20)
                self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_calculate_cpu8(self):
        container_stats = {
            'cpu_stats': {'cpu_usage': {'percpu_usage': [35, 1],
                                        'total_usage': 36},
                          'system_cpu_usage': 200},
            'precpu_stats': {'cpu_usage': {'total_usage': 10},
                             'system_cpu_usage': 0,
                             }
        }
        container_info = {
            'State': {'Running': True},
            "HostConfig": {
                "NanoCpus": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
            }

        }

        pecentage = check_docker.calculate_cpu_capacity_precentage(info=container_info, stats=container_stats)
        self.assertEqual(pecentage, 13)

    def test_require_running(self):
        """ This the 'require_running decorator is working properly with a stopped container"""
        container_info = {'RestartCount': 0, 'State': {'Running': False}}

        with patch('check_docker.get_container_info', return_value=container_info):
            check_docker.check_restarts(container='container', warn=1, crit=2)
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_restarts1(self):
        container_info = {'RestartCount': 0, 'State': {'Running': True}}

        with patch('check_docker.get_container_info', return_value=container_info):
            check_docker.check_restarts(container='container', warn=1, crit=2)
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_restarts2(self):
        container_info = {'RestartCount': 1, 'State': {'Running': True}}

        with patch('check_docker.get_container_info', return_value=container_info):
            check_docker.check_restarts(container='container', warn=1, crit=2)
            self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_restarts3(self):
        container_info = {'RestartCount': 3, 'State': {'Running': True}}

        with patch('check_docker.get_container_info', return_value=container_info):
            check_docker.check_restarts(container='container', warn=1, crit=2)
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_uptime1(self):
        now_string = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string,
                      'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container='container', warn=10, crit=5)
            self.assertEqual(check_docker.rc, check_docker.CRITICAL_RC)

    def test_check_uptime2(self):
        ten = timedelta(seconds=10)
        then = datetime.now(tz=timezone.utc) - ten
        now_string = then.strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string,
                      'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container='container', warn=20, crit=1)
            self.assertEqual(check_docker.rc, check_docker.WARNING_RC)

    def test_check_uptime3(self):
        ten = timedelta(seconds=10)
        then = datetime.now(tz=timezone.utc) - ten
        now_string = then.strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string,
                      'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container='container', warn=2, crit=1)
            self.assertEqual(check_docker.rc, check_docker.OK_RC)

    def test_check_uptime4(self):
        ten = timedelta(days=1, seconds=0)
        then = datetime.now(tz=timezone.utc) - ten
        now_string = then.strftime("%Y-%m-%dT%H:%M:%S")
        now_string += ".0000000000Z"
        json_results = {
            'State': {'StartedAt': now_string,
                      'Running': True},
        }
        with patch('check_docker.get_url', return_value=json_results):
            check_docker.check_uptime(container='container', warn=2, crit=1)
            self.assertEqual(check_docker.rc, check_docker.OK_RC)


class TestArgs(unittest.TestCase):

    sample_containers_json = [
            {'Names': ['/thing1']},
            {'Names': ['/thing2']}
        ]

    def setUp(self):
        check_docker.rc = -1

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

    def test_args_present(self):
        result = check_docker.process_args(args=())
        self.assertFalse(result.present)
        args = ('--present',)
        result = check_docker.process_args(args=args)
        self.assertTrue(result.present)

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

    def test_get_containers_1(self):
        with patch('check_docker.get_url', return_value=self.sample_containers_json):
            container_list = check_docker.get_containers('all', False)
            self.assertSetEqual(container_list, {'thing1', 'thing2'})

    def test_get_containers_2(self):
        with patch('check_docker.get_url', return_value=self.sample_containers_json):
            container_list = check_docker.get_containers(['thing.*'], False)
            self.assertSetEqual(container_list, {'thing1', 'thing2'})

    def test_get_containers_3(self):
        with patch('check_docker.get_url', return_value=self.sample_containers_json):
            with patch('check_docker.unknown') as patched:
                container_list = check_docker.get_containers({'foo'}, False)
                self.assertSetEqual(container_list, set())
                self.assertEqual(patched.call_count, 0)

    def test_get_containers_4(self):
        with patch('check_docker.get_url', return_value=self.sample_containers_json):
            with patch('check_docker.critical') as patched:
                container_list = check_docker.get_containers({'foo'}, True)
                self.assertSetEqual(container_list, set())
                self.assertEqual(patched.call_count, 1)

class TestSocket(fake_filesystem_unittest.TestCase):
    def setUp(self):
        check_docker.rc = -1
        check_docker.messages = []
        check_docker.performance_data = []
        self.setUpPyfakefs()

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


class TestPerform(fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.containers = [{'Names': ['/thing1']}, ]

    def test_no_containers(self):
        args = ['--cpu', '0:0']
        with patch('check_docker.get_url', return_value=[]):
            with patch('check_docker.unknown') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_cpu(self):
        args = ['--cpu', '0:0']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_cpu') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_mem(self):
        args = ['--memory', '0:0']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_memory') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_health(self):
        args = ['--health']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_health') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_restarts(self):
        args = ['--restarts', '1:1']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_restarts') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_status(self):
        args = ['--status', 'running']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_status') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_uptime(self):
        args = ['--uptime', '0:0']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_uptime') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_version(self):
        args = ['--version']
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.check_version') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)

    def test_check_no_checks(self):
        args = []
        with patch('check_docker.get_url', return_value=self.containers):
            with patch('check_docker.unknown') as patched:
                check_docker.perform_checks(args)
                self.assertEqual(patched.call_count, 1)


class TestOutput(unittest.TestCase):
    def setUp(self):
        check_docker.messages = []
        check_docker.performance_data = []

    check_docker.messages = []

    def test_print_results1(self):
        check_docker.messages = []
        check_docker.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, '')

    def test_print_results2(self):
        check_docker.messages = ['TEST']
        check_docker.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, 'TEST')

    def test_print_results3(self):
        check_docker.messages = ['FOO', 'BAR']
        check_docker.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, 'FOO; BAR')

    def test_print_results4(self):
        check_docker.messages = ['FOO', 'BAR']
        check_docker.performance_data = ['1;2;3;4;']

        check_docker.print_results()
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, 'FOO; BAR|1;2;3;4;')


class TestVersion(unittest.TestCase):

    def test_package_present(self):
        req = request.Request("https://pypi.python.org/pypi?:action=doap&name=check_docker", method="HEAD")
        with request.urlopen(req) as resp:
            self.assertEqual(resp.getcode(), 200)

    def test_ensure_new_version(self):
        version = check_docker.__version__
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
