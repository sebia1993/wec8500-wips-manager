"""Supplemental assurance for the unchanged stabilization.3 application.

Synthetic values, isolated temporary files and loopback sockets only. Failures
are injected at persistence boundaries; the Runner and journal remain real.
"""
from __future__ import annotations

import copy
import csv
import errno
from pathlib import Path
import queue
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from wec_wips.core import Result, RunConfig, Runner, export_results
from wec_wips.gui import WipsApp
from wec_wips.journal import LocalJournal
from wec_wips.reports import export_ap_txts, write_report_bundle


def demo_config():
    return RunConfig('192.0.2.1', 23, 'operator', 'SYNTHETIC_CTL_PASSWORD',
                     ['192.0.2.11', '192.0.2.12'], 50022, 'root',
                     'SYNTHETIC_AP_PASSWORD', demo=True)


def sample_results():
    return [Result('2026-11-12T00:00:00+09:00', f'192.0.2.{i}', '조회완료',
                   mode='inspect', simulated=True, hostname=f'LAB-{i}',
                   summary_before='wips sharedkey : SyntheticReadKey')
            for i in (11, 12)]


class JournalPersistenceAssuranceTests(unittest.TestCase):
    def run_job(self, folder, injection):
        app = WipsApp.__new__(WipsApp)
        app.events, app.stop_event = queue.Queue(), threading.Event()
        app._worker_confirm = lambda *_: self.fail('Demo job must not request host trust')
        journals = []
        def real_journal(config, mode):
            journal = LocalJournal(config, mode, base_dir=folder)
            journals.append(journal)
            return journal
        with patch('wec_wips.journal.LocalJournal', side_effect=real_journal), injection:
            app._run(demo_config(), 'inspect')
        events = list(app.events.queue)
        kinds = [kind for kind, _ in events]
        rows = [data['result'] for kind, data in events if kind == 'result']
        self.assertEqual([row.ap_ip for row in rows], demo_config().ap_ips)
        self.assertEqual([row.status for row in rows], ['조회완료', '조회완료'])
        self.assertEqual(kinds.count('local_record_error'), 1)
        self.assertEqual(kinds[-1], 'worker_end')
        self.assertIn('done', kinds)
        self.assertNotIn('worker_error', kinds)
        self.assertFalse(app.stop_event.is_set())
        self.assertNotIn('SYNTHETIC_FAILURE_SECRET', repr(events))
        for journal in journals:
            self.assertTrue(journal._events.closed)
            self.assertTrue(journal._csv.closed)
        return journals, rows

    def test_state_replace_failure_does_not_drop_ap_results(self):
        import os
        real_replace = os.replace
        counts = {'state': 0}
        def failing_replace(src, dst):
            if Path(dst).name == 'state.json':
                counts['state'] += 1
                if counts['state'] > 1:
                    raise OSError(errno.ENOSPC, 'SYNTHETIC_FAILURE_SECRET')
            return real_replace(src, dst)
        with tempfile.TemporaryDirectory() as folder:
            journals, rows = self.run_job(folder, patch('wec_wips.journal.os.replace', side_effect=failing_replace))
            self.assertGreater(counts['state'], 1)
            self.assertFalse(list(Path(folder).rglob('*.tmp')))
            # Results remain exportable through the ordinary operator path.
            target = Path(folder) / 'manual.csv'
            export_results(target, rows)
            with target.open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 2)

    def test_journal_csv_write_failure_preserves_memory_results_and_masking(self):
        real_writerow = csv.DictWriter.writerow
        failures = []
        def fail_result(writer, row):
            if row.get('ap_ip') == '192.0.2.11':
                failures.append(dict(row))
                raise OSError(errno.ENOSPC, 'SYNTHETIC_FAILURE_SECRET')
            return real_writerow(writer, row)
        with tempfile.TemporaryDirectory() as folder:
            journals, rows = self.run_job(folder, patch('csv.DictWriter.writerow', new=fail_result))
            self.assertEqual(len(failures), 1)
            self.assertIn('[MASKED]', failures[0]['summary_before'])
            self.assertIn('DemoOldKey', rows[0].summary_before)
            stored = '\n'.join(path.read_text('utf-8-sig')
                               for path in journals[0].directory.iterdir() if path.is_file())
            for secret in ('SYNTHETIC_CTL_PASSWORD', 'SYNTHETIC_AP_PASSWORD', 'DemoOldKey'):
                self.assertNotIn(secret, stored)

    def test_journal_creation_failure_still_completes_the_real_runner(self):
        # A file at the configured directory location is an actual filesystem
        # failure, rather than a replacement Runner or a fabricated result.
        with tempfile.TemporaryDirectory() as folder:
            blocked = Path(folder) / 'not_a_directory'
            blocked.write_text('unchanged')
            journals, _ = self.run_job(blocked, patch('wec_wips.transport.TelnetChannel.connect',
                                                    side_effect=AssertionError('Demo must not connect')))
            self.assertEqual(journals, [])
            self.assertEqual(blocked.read_text(), 'unchanged')


class ExportCleanupAssuranceTests(unittest.TestCase):
    def test_report_publish_failure_removes_only_its_staging_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            old = parent / 'previous-report'
            old.mkdir()
            (old / 'report.html').write_bytes(b'PREVIOUS REPORT')
            rows = sample_results()
            snapshot = copy.deepcopy(rows)
            with patch('wec_wips.reports.Path.rename', side_effect=PermissionError('synthetic lock')):
                with self.assertRaises(PermissionError):
                    write_report_bundle(parent, rows)
            self.assertEqual(list(parent.iterdir()), [old])
            self.assertEqual((old / 'report.html').read_bytes(), b'PREVIOUS REPORT')
            self.assertEqual(rows, snapshot)

    def test_second_txt_failure_does_not_publish_an_incomplete_bundle(self):
        import os
        real_replace = os.replace
        reached = []
        def fail_second(src, dst):
            reached.append(Path(dst).name)
            if Path(dst).name == '192.0.2.12.txt':
                raise OSError(errno.ENOSPC, 'synthetic full disk')
            return real_replace(src, dst)
        with tempfile.TemporaryDirectory() as folder:
            old = Path(folder) / 'previous.txt'
            old.write_bytes(b'PREVIOUS TXT')
            with patch('wec_wips.reports.os.replace', side_effect=fail_second):
                with self.assertRaises(OSError):
                    export_ap_txts(folder, sample_results())
            self.assertEqual(reached, ['192.0.2.11.txt', '192.0.2.12.txt'])
            self.assertEqual(list(Path(folder).iterdir()), [old])
            self.assertEqual(old.read_bytes(), b'PREVIOUS TXT')

    def test_csv_staging_creation_failure_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'existing.csv'
            target.write_bytes(b'PREVIOUS CSV')
            rows = sample_results()
            with patch('wec_wips.core.tempfile.mkstemp', side_effect=PermissionError('synthetic denial')):
                with self.assertRaises(PermissionError):
                    export_results(target, rows)
            self.assertEqual(target.read_bytes(), b'PREVIOUS CSV')
            self.assertEqual(list(Path(folder).iterdir()), [target])


class LoginCancellationAssuranceTests(unittest.TestCase):
    def check_phase(self, phase):
        stop = threading.Event()
        captured, sent = {}, []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(4)
        cfg = RunConfig('127.0.0.1', listener.getsockname()[1], 'operator', 'SyntheticCtlPW',
                        ['192.0.2.11', '192.0.2.12'], 50022, 'root', 'SyntheticApPW', timeout=2)
        def run():
            try:
                captured['rows'] = Runner(cfg, lambda *_: None, lambda *_: True, stop).run('inspect')
            except BaseException as exc:
                captured['error'] = type(exc).__name__
        worker = threading.Thread(target=run, name='test-login-cancel')
        peer = None
        try:
            worker.start()
            peer, _ = listener.accept()
            peer.settimeout(4)
            def exchange(reply, expected):
                peer.sendall(reply.encode())
                data = bytearray()
                while not data.endswith(b'\n'):
                    chunk = peer.recv(1)
                    if not chunk:
                        self.fail('Client disconnected before cancellation')
                    data.extend(chunk)
                line = data.rstrip(b'\r\n').decode()
                sent.append(line)
                self.assertEqual(line, expected)
            if phase in ('controller_password', 'ap_password'):
                exchange('Username:', cfg.controller_user)
            if phase == 'ap_password':
                exchange('Password:', cfg.controller_password)
                exchange('WEC8500#', 'ssh 192.0.2.11 root 50022')
            # Withhold the next prompt and cancel while the actual transport waits.
            stop.set()
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertNotIn('error', captured)
            self.assertEqual(peer.recv(1), b'')
            self.assertEqual([row.status for row in captured['rows']], ['중지', '미실행'])
            self.assertFalse(any(row.config_sent for row in captured['rows']))
            self.assertEqual(captured['rows'][0].error_code, 'CANCELLED')
            self.assertEqual(captured['rows'][0].attempts, 1)
            self.assertNotIn(cfg.ap_password, sent)
            if phase != 'ap_password':
                self.assertNotIn(cfg.controller_password, sent)
            self.assertFalse(any('192.0.2.12' in line or line.startswith('config ') for line in sent))
        finally:
            stop.set()
            if peer is not None:
                peer.close()
            listener.close()
            if worker.ident is not None:
                worker.join(5)
            self.assertFalse(worker.is_alive())

    def test_cancel_before_controller_username_closes_connection(self):
        self.check_phase('controller_username')

    def test_cancel_before_controller_password_does_not_send_password(self):
        self.check_phase('controller_password')

    def test_cancel_before_ap_password_does_not_send_ap_password(self):
        self.check_phase('ap_password')


if __name__ == '__main__':
    unittest.main()
