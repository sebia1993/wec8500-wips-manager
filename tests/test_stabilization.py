"""Behavior-preserving regressions using synthetic data and in-memory peers."""
from collections import deque
import csv
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_transport import Peer
from wec_wips.core import RunConfig, Result, Runner, SUMMARY_COMMAND, export_results
from wec_wips.transport import Session, TransportError, parse_ap_names
from wec_wips.reports import write_report_bundle, export_ap_txts


def config():
    return RunConfig('192.0.2.1', 23, 'operator', 'SyntheticCtlPassword',
                     ['192.0.2.11', '192.0.2.12'], 50022, 'root',
                     'SyntheticAPPassword', server_ip='192.0.2.99',
                     shared_key='SyntheticTargetKey', lookup_hostnames=True)


HEADER = 'AP_ID Profile AP_NAME MAC_Address IPv4Addr\r\n'


def inventory(*names):
    return HEADER + ''.join(
        f'{index} default {name} 00:11:22:33:44:{index:02x} 192.0.2.11\r\n'
        for index, name in enumerate(names, 1))


class InventoryStabilityTests(unittest.TestCase):
    def test_generic_first_conflict_excludes_name_without_exception(self):
        # Previously names.pop() removed an entry that generic filtering never added.
        for first in ('AP', 'root', 'localhost', '192.0.2.11'):
            with self.subTest(first=first):
                try:
                    actual = parse_ap_names(inventory(first, 'LAB-AP11'))
                except KeyError as exc:
                    self.fail(f'Conflicting filtered name must not raise KeyError: {exc}')
                self.assertEqual(actual, {})

    def test_existing_valid_duplicates_and_conflict_policy_are_unchanged(self):
        self.assertEqual(parse_ap_names(inventory('LAB-AP11', 'LAB-AP11')),
                         {'192.0.2.11': 'LAB-AP11'})
        self.assertEqual(parse_ap_names(inventory('LAB-AP11', 'OTHER', 'LAB-AP11')), {})
        self.assertEqual(parse_ap_names(inventory('LAB-AP11', 'AP')), {})

    def test_inventory_conflict_does_not_abort_inspect_or_send_config(self):
        cfg = config()
        cfg.ap_hostnames = {'192.0.2.11': 'CSV-AP11'}
        peer = Peer({
            'operator\n': [b'Password:'], 'SyntheticCtlPassword\n': [b'WEC8500#'],
            'show ap summary\n': [(inventory('AP', 'LAB-AP11') + 'WEC8500#').encode()],
            'ssh 192.0.2.11 root 50022\n': [b'Password:'],
            'ssh 192.0.2.12 root 50022\n': [b'Password:'],
            'SyntheticAPPassword\n': [b'AP#'],
            SUMMARY_COMMAND + '\n': [b'wips server ip : 192.0.2.99\r\nwips nat : 1\r\nwips sharedkey : SyntheticReadKey\r\nAP#'],
            'exit\n': [b'WEC8500#'],
        })
        with patch('wec_wips.transport.TelnetChannel.connect', return_value=peer) as connect:
            results = Runner(cfg, lambda *_: None, lambda *_: True, threading.Event()).run('inspect')
        self.assertEqual([r.status for r in results], ['조회완료', '조회완료'])
        self.assertEqual(results[0].hostname, 'CSV-AP11')
        self.assertEqual(results[0].hostname_source, 'CSV')
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(peer.sent.count('show ap summary\n'), 1)
        self.assertEqual(peer.sent.count('exit\n'), 2)
        self.assertFalse(any(x.startswith('config ') for x in peer.sent))
        self.assertTrue(peer.closed)


class ChunkPeer:
    def __init__(self, chunks):
        self.pending = deque(chunks)
        self.closed = False
        self.sent = []
    def recv_ready(self):
        return bool(self.pending)
    def recv(self, count):
        return self.pending.popleft()
    def sendall(self, data):
        self.sent.append(data)
    def close(self):
        self.closed = True


def read_chunks(chunks):
    session = Session(config(), threading.Event(), lambda *_: True)
    session._channel = ChunkPeer(chunks)
    actual = ''
    while session._channel.recv_ready():
        actual, _ = session._read_more(actual)
    return session, actual


class Utf8StabilityTests(unittest.TestCase):
    def test_every_byte_boundary_preserves_valid_utf8_reply(self):
        expected = 'wips sharedkey : KEY가é🙂123\r\nAP#'
        wire = expected.encode('utf-8')
        for split in range(1, len(wire)):
            with self.subTest(split=split):
                session, actual = read_chunks([wire[:split], wire[split:]])
                self.addCleanup(session.close)
                self.assertEqual(actual, expected)

    def test_byte_at_a_time_reply_reaches_existing_operator_exports(self):
        expected = 'wips server ip : 192.0.2.99\r\nwips nat : 1\r\nwips sharedkey : KEY가123\r\n'
        session, response = read_chunks([bytes([b]) for b in expected.encode('utf-8')])
        self.addCleanup(session.close)
        runner = Runner(config(), lambda *_: None, lambda *_: True, threading.Event())
        result = Result('2026-11-11T00:00:00+09:00', '192.0.2.11', '조회완료', mode='inspect')
        runner._capture_summary(result, response, 'inspect')
        self.assertIn('KEY가123', result.summary_before)
        with tempfile.TemporaryDirectory() as directory:
            bundle = write_report_bundle(directory, [result])
            txts = export_ap_txts(directory, [result])
            export_results(Path(directory) / 'direct.csv', [result])
            for path in (bundle / 'report.html', bundle / 'results.csv',
                         txts / 'details/192.0.2.11.txt', Path(directory) / 'direct.csv'):
                self.assertIn('KEY가123', path.read_text('utf-8-sig'))

    def test_invalid_bytes_keep_existing_replacement_policy(self):
        wire = b'left\xffright\xe1A\r\n'
        session, actual = read_chunks([wire[:7], wire[7:]])
        self.addCleanup(session.close)
        self.assertEqual(actual, wire.decode('utf-8', errors='replace'))

    def test_close_resets_incomplete_character_state(self):
        session, _ = read_chunks([b'\xea'])
        session.close()
        session._channel = ChunkPeer([b'ASCII\r\nAP#'])
        actual, _ = session._read_more('')
        self.assertEqual(actual, 'ASCII\r\nAP#')
        session.close()

    def test_pending_incomplete_unsolicited_data_never_allows_command(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        peer = ChunkPeer([b'\xea'])
        session._channel = peer
        session._ready = True
        session._ap_prompt, session._controller_prompt = 'AP#', 'WEC8500#'
        with self.assertRaises(TransportError) as caught:
            session.execute('config wips server 192.0.2.99 1 SyntheticTargetKey')
        self.assertEqual(caught.exception.code, 'UNEXPECTED_DATA')
        self.assertEqual(peer.sent, [])
        self.assertTrue(peer.closed)

    def test_partial_suffix_after_login_prompt_does_not_send_username(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        peer = ChunkPeer([b'Username:\xea'])
        session._channel = peer
        self.addCleanup(session.close)
        with self.assertRaises(TransportError):
            session._wait_controller_login()
        self.assertEqual(peer.sent, [])

    def test_partial_suffix_after_password_prompt_does_not_send_password(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        peer = Peer({'operator\n': [b'Password:\xea']}, initial=[b'Username:'])
        session._channel = peer
        self.addCleanup(session.close)
        with self.assertRaises(TransportError):
            session._wait_controller_login()
        self.assertEqual(peer.sent, ['operator\n'])

    def test_partial_ap_password_prompt_does_not_send_password(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        peer = ChunkPeer([b'Password:\xea'])
        session._channel = peer
        session._controller_prompt = 'WEC8500#'
        self.addCleanup(session.close)
        with self.assertRaises(TransportError):
            session._wait_ap_login('192.0.2.11')
        self.assertEqual(peer.sent, [])

    def test_partial_inventory_auth_text_retains_timeout_classification(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        session._channel = ChunkPeer([b'Password:\xea'])
        session._controller_prompt = 'WEC8500#'
        self.addCleanup(session.close)
        with self.assertRaises(TransportError) as caught:
            session._wait_inventory()
        self.assertEqual(caught.exception.code, 'COMMAND_TIMEOUT')

    def test_partial_suffix_after_host_question_does_not_send_yes(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        peer = ChunkPeer([b'Continue connecting (yes/no)?\xea'])
        session._channel = peer
        session._controller_prompt = 'WEC8500#'
        self.addCleanup(session.close)
        with self.assertRaises(TransportError):
            session._wait_ap_login('192.0.2.11')
        self.assertEqual(peer.sent, [])

    def test_prompt_followed_by_incomplete_byte_is_not_a_complete_reply(self):
        session = Session(config(), threading.Event(), lambda *_: True)
        session.config.timeout = 0.12
        session._ap_prompt, session._controller_prompt = 'AP#', 'WEC8500#'
        session._channel = ChunkPeer([b'wips server ip : 192.0.2.99\r\nAP#\xea'])
        self.addCleanup(session.close)
        with self.assertRaises(TransportError) as caught:
            session._wait_command()
        self.assertEqual(caught.exception.code, 'COMMAND_TIMEOUT')


class CsvPreservationTests(unittest.TestCase):
    def sample(self):
        return Result('2026-11-11T00:00:00+09:00', '192.0.2.11', '조회완료',
                      message='=formula', summary_before='wips sharedkey : SyntheticReadKey')

    def test_interrupted_csv_write_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'existing.csv'
            original = b'PREVIOUS SUCCESSFUL EXPORT\r\n'
            target.write_bytes(original)
            real_write = csv.DictWriter.writerow
            def fail_on_result(writer, row):
                if row.get('ap_ip') == '192.0.2.11':
                    raise OSError('simulated disk write failure')
                return real_write(writer, row)
            with patch('csv.DictWriter.writerow', new=fail_on_result):
                with self.assertRaises(OSError):
                    export_results(target, [self.sample()])
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['existing.csv'])

    def test_interrupted_new_csv_write_leaves_no_incomplete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new.csv'
            with patch('csv.DictWriter.writerow', side_effect=OSError('simulated failure')):
                with self.assertRaises(OSError):
                    export_results(target, [self.sample()])
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_replace_failure_preserves_previous_file_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'existing.csv'
            target.write_bytes(b'previous')
            with patch('wec_wips.core.os.replace', side_effect=PermissionError('locked target')):
                with self.assertRaises(PermissionError):
                    export_results(target, [self.sample()])
            self.assertEqual(target.read_bytes(), b'previous')
            self.assertEqual([p.name for p in Path(directory).iterdir()], ['existing.csv'])

    def test_success_csv_bytes_and_field_order_remain_identical(self):
        from dataclasses import fields
        from wec_wips.core import _safe_cell
        result = self.sample()
        names = [f.name for f in fields(Result)]
        expected = io.StringIO(newline='')
        writer = csv.DictWriter(expected, fieldnames=names)
        writer.writeheader()
        writer.writerow({name: _safe_cell(getattr(result, name)) for name in names})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.csv'
            export_results(target, [result])
            self.assertEqual(target.read_bytes(), expected.getvalue().encode('utf-8-sig'))


class PolicyPreservationTests(unittest.TestCase):
    def test_masked_recovery_keeps_existing_partial_status_and_no_resend(self):
        cfg = config()
        result = Result('2026-11-11T00:00:00+09:00', '192.0.2.11', '확인불가',
                        mode='apply', target_ip=cfg.server_ip, config_sent=True,
                        expected_nat='1', before_ip='192.0.2.10', before_nat='1')
        sent = []
        class ReadOnlyPeer:
            def execute(self, command):
                sent.append(command)
                return 'wips server ip : 192.0.2.10\nwips nat : 1\nwips sharedkey : ******\n'
        Runner(cfg, lambda *_: None, lambda *_: True, threading.Event())._perform(ReadOnlyPeer(), 'apply', result)
        self.assertEqual(sent, [SUMMARY_COMMAND])
        self.assertEqual(result.status, '부분확인')
        self.assertEqual(result.ip_check, '불일치')
        self.assertEqual(result.error_code, 'RECOVERY_UNVERIFIABLE')


if __name__ == '__main__':
    unittest.main()
