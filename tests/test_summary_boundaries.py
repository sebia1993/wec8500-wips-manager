"""Line-bounded summary parsing; synthetic fixtures and loopback TCP only."""
from __future__ import annotations

from itertools import permutations
import threading
import unittest

from test_recovery_integration import _RecoveryController
from wec_wips.core import RunConfig, Result, Runner, SUMMARY_COMMAND, parse_summary


def config():
    return RunConfig('192.0.2.1', 23, 'operator', 'SyntheticCtlPW',
                     ['192.0.2.11'], 50022, 'root', 'SyntheticApPW',
                     server_ip='192.0.2.99', shared_key='SyntheticTargetKey')


def response(key='', separator=' : ', newline='\n'):
    return newline.join((
        'wips server ip' + separator + '192.0.2.99',
        'wips nat' + separator + '1',
        'wips sharedkey' + separator + key,
        'wips mode' + separator + 'WIPS_SENSOR_MODE',
    )) + newline


class SummaryLineBoundaryTests(unittest.TestCase):
    def test_empty_key_never_consumes_next_named_field(self):
        for separator in (' : ', ' = ', ' ........ ', ' '):
            for newline in ('\n', '\r\n'):
                with self.subTest(separator=separator, newline=repr(newline)):
                    actual = parse_summary(response(separator=separator, newline=newline))
                    self.assertIsNone(actual.shared_key)
                    self.assertEqual(actual.server_ip, '192.0.2.99')
                    self.assertEqual(actual.nat, '1')
                    self.assertEqual(actual.mode, 'WIPS_SENSOR_MODE')

    def test_empty_key_is_unknown_for_all_field_orders(self):
        rows = response().splitlines()
        for order in permutations(rows):
            with self.subTest(order=order):
                actual = parse_summary('\n'.join(order) + '\n')
                self.assertIsNone(actual.shared_key)
                self.assertEqual(actual.server_ip, '192.0.2.99')
                self.assertEqual(actual.nat, '1')
                self.assertEqual(actual.mode, 'WIPS_SENSOR_MODE')

    def test_empty_key_does_not_consume_prompt_or_notice(self):
        base = 'wips server ip : 192.0.2.99\nwips nat : 1\nwips sharedkey : \t\n'
        for next_line in ('AP_TEST#', 'Device notice', 'wips mode : WIPS_SENSOR_MODE'):
            with self.subTest(next_line=next_line):
                self.assertIsNone(parse_summary(base + next_line + '\n').shared_key)

    def test_empty_mode_does_not_consume_server_ip_field(self):
        actual = parse_summary('wips mode : \n' + response().replace('wips mode : WIPS_SENSOR_MODE\n', ''))
        self.assertEqual(actual.mode, '')
        self.assertEqual(actual.server_ip, '192.0.2.99')

    def test_label_split_across_lines_is_not_a_complete_field(self):
        text = 'wips server\nip : 192.0.2.99\nwips nat : 1\nwips sharedkey : SyntheticKey\n'
        with self.assertRaises(ValueError):
            parse_summary(text)

    def test_server_ip_from_next_line_is_not_accepted_as_field_value(self):
        text = 'wips server ip : \n192.0.2.99\nwips nat : 1\nwips sharedkey : SyntheticKey\n'
        with self.assertRaises(ValueError):
            parse_summary(text)

    def test_valid_existing_formats_keep_values_and_masking(self):
        for key, expected in (('SyntheticKey!#', 'SyntheticKey!#'),
                              ('KEY가123', 'KEY가123'), ('******', None),
                              ('[MASKED]', None), ('<hidden>', None)):
            for separator in (' : ', ' = ', ' ........ ', '\t'):
                with self.subTest(key=key, separator=repr(separator)):
                    actual = parse_summary(response(key=key, separator=separator, newline='\r\n'))
                    self.assertEqual((actual.server_ip, actual.nat, actual.shared_key, actual.mode),
                                     ('192.0.2.99', '1', expected, 'WIPS_SENSOR_MODE'))

    def test_duplicate_empty_and_nonempty_fields_are_still_rejected(self):
        for extra in ('wips sharedkey : OtherKey\n', 'wips server ip : 192.0.2.99\n',
                      'wips nat : 1\n', 'wips mode : WIPS_SENSOR_MODE\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                parse_summary(response() + extra)

    def test_empty_nat_still_rejects_summary(self):
        with self.assertRaises(ValueError):
            parse_summary(response().replace('wips nat : 1', 'wips nat : '))


class RecoveryBoundaryTests(unittest.TestCase):
    def test_ambiguous_write_with_empty_key_requeries_without_resend(self):
        cfg = config()
        prior = Result('2026-11-12T00:00:00+09:00', cfg.ap_ips[0], '확인불가',
                       mode='apply', config_sent=True, expected_nat='1',
                       before_ip='192.0.2.10', before_nat='1', attempts=1)
        sent = []
        class Peer:
            controller_ready = False
            def __init__(self, *_): pass
            def connect(self, _): self.controller_ready = False
            def execute(self, command):
                sent.append(command)
                return response()
            def leave_ap(self): self.controller_ready = True
            def close(self): self.controller_ready = False
        rows = Runner(cfg, lambda *_: None, lambda *_: False, threading.Event(),
                      session_factory=Peer, resume_results=[prior]).run('apply')
        self.assertEqual(sent, [SUMMARY_COMMAND])
        self.assertEqual(rows[0].status, '부분확인')
        self.assertEqual(rows[0].error_code, 'RECOVERY_UNVERIFIABLE')
        self.assertEqual(rows[0].key_check, '확인불가')
        self.assertTrue(rows[0].config_sent)
        self.assertEqual(rows[0].expected_nat, '1')
        self.assertEqual(rows[0].controller_return, '복귀확인')

    def test_post_write_empty_key_uses_existing_partial_verification(self):
        cfg = config()
        sent = []
        class Peer:
            def execute(self, command):
                sent.append(command)
                if len(sent) == 1:
                    return response(key='SyntheticOldKey').replace('192.0.2.99', '192.0.2.10')
                return response()
        result = Result('2026-11-12', cfg.ap_ips[0], '미실행', mode='apply')
        Runner(cfg, lambda *_: None, lambda *_: False, threading.Event())._perform(Peer(), 'apply', result)
        self.assertEqual(sum(cmd.startswith('config ') for cmd in sent), 1)
        self.assertEqual(result.status, '부분확인')
        self.assertEqual(result.key_check, '확인불가')
        self.assertEqual(result.error_code, 'VERIFICATION_PARTIAL')

    def test_loopback_disconnect_then_empty_key_never_repeats_configuration(self):
        class BlankKeyController(_RecoveryController):
            def _session(self, peer, connection):
                class ReplyAdapter:
                    def sendall(self, payload):
                        if b'wips sharedkey ........ ********\r\n' in payload:
                            payload = payload.replace(b'wips mode ........ WIPS_SENSOR_MODE\r\n', b'')
                            payload = payload.replace(
                                b'wips sharedkey ........ ********\r\n',
                                b'wips sharedkey ........ \r\nwips mode ........ WIPS_SENSOR_MODE\r\n')
                        peer.sendall(payload)
                    def recv(self, count):
                        return peer.recv(count)
                super()._session(ReplyAdapter(), connection)
        with BlankKeyController('masked_after_write') as server:
            cfg = RunConfig('127.0.0.1', server.port, 'testoperator', 'ControllerRecoverySecret',
                            ['192.0.2.10', '192.0.2.11'], 50022, 'root', 'APRecoverySecret',
                            server_ip='198.51.100.20', shared_key='NewRecoveryKey', timeout=2,
                            retry_delays=(0.0, 0.0))
            rows = Runner(cfg, lambda *_: None, lambda *_: True, threading.Event()).run('apply')
            commands = list(server.commands)
            connections = server.connections
        self.assertFalse(server.errors, server.errors)
        writes = [cmd for _, phase, _, cmd in commands if phase == 'ap' and cmd.startswith('config ')]
        self.assertEqual(len(writes), 1, 'An unobservable key must not authorize replay of an uncertain write')
        self.assertEqual(connections, 2)
        self.assertEqual([r.status for r in rows], ['부분확인', '미실행'])
        self.assertEqual(rows[0].key_check, '확인불가')
        self.assertEqual(rows[0].error_code, 'RECOVERY_UNVERIFIABLE')
        self.assertEqual([cmd for n, phase, _, cmd in commands if n == 2 and phase == 'ap'],
                         [SUMMARY_COMMAND, 'exit'])


if __name__ == '__main__':
    unittest.main()
