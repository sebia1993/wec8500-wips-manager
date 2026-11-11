"""Resource-failure regressions; no equipment or new application features."""
from __future__ import annotations

import copy
import gc
import socket
import threading
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_gui import destroy_test_root
from wec_wips.core import DemoSession, Result, RunConfig, Runner, SUMMARY_COMMAND
from wec_wips.gui import WipsApp


class WorkerStartFailureTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        self.app = WipsApp(self.root)
        self.app._fill_demo()
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name,
                                            'LOCALAPPDATA': self.temp.name})
        self.env.start()

    def tearDown(self):
        worker = self.app.worker
        if worker is not None and worker.is_alive():
            self.app.stop_event.set()
            worker.join(5)
            self.assertFalse(worker.is_alive(), 'Test worker must not leak')
        destroy_test_root(self.root)
        self.app = self.root = None
        gc.collect()
        self.env.stop()
        self.temp.cleanup()

    def fail_start(self, operation):
        # RuntimeError is how Thread.start reports an OS thread creation failure.
        with patch('wec_wips.gui.threading.Thread.start',
                   side_effect=RuntimeError('SYNTHETIC_INTERNAL_SECRET: no thread resources')):
            try:
                operation()
            except RuntimeError:
                self.fail('Worker creation failure escaped and left the UI busy')
        self.app._pump()
        self.assertFalse(self.app.busy)
        self.assertFalse(self.app.ui_failed)
        self.assertEqual(str(self.app.inspect_button['state']), 'normal')
        self.assertEqual(str(self.app.stop_button['state']), 'disabled')
        self.assertNotIn('SYNTHETIC_INTERNAL_SECRET', self.app.status.get())
        self.assertNotIn('SYNTHETIC_INTERNAL_SECRET', self.app.log.get('1.0', 'end'))

    def test_new_job_thread_start_failure_releases_ui_without_network(self):
        cfg = self.app._snapshot('inspect')
        with patch('wec_wips.transport.TelnetChannel.connect') as connect:
            self.fail_start(lambda: self.app._begin(cfg, 'inspect'))
        connect.assert_not_called()
        self.assertEqual(self.app.results, [])
        self.assertEqual(self.app.saved_config.ap_ips, cfg.ap_ips)
        self.assertEqual(str(self.app.resume_button['state']), 'normal')

    def test_resume_start_failure_preserves_uncertain_write_evidence(self):
        cfg = self.app._snapshot('apply')
        prior = [Result('2026-11-11T00:00:00+09:00', cfg.ap_ips[0], '확인불가',
                        mode='apply', simulated=True, config_sent=True, expected_nat='2',
                        before_ip='192.0.2.200', before_nat='2', attempts=2,
                        summary_before='wips sharedkey : SyntheticOldKey')]
        expected = copy.deepcopy(prior)
        self.fail_start(lambda: self.app._begin(cfg, 'apply', copy.deepcopy(prior)))
        self.assertEqual(self.app.results, expected)
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.assertEqual(str(self.app.resume_button['state']), 'normal')

    def test_export_start_failure_preserves_results_and_existing_destination(self):
        cfg = self.app._snapshot('inspect')
        rows = [Result('2026-11-11T00:00:00+09:00', cfg.ap_ips[0], '조회완료',
                       mode='inspect', simulated=True,
                       summary_before='wips sharedkey : SyntheticOldKey')]
        self.app.results = copy.deepcopy(rows)
        self.app.saved_config, self.app.saved_mode = cfg, 'inspect'
        target = Path(self.temp.name) / 'previous.csv'
        target.write_bytes(b'PREVIOUS REPORT')
        for kind in ('csv', 'report', 'txt'):
            with self.subTest(kind=kind):
                self.fail_start(lambda: self.app._launch_export(kind, target, self.app.results))
                self.assertFalse(self.app.exporting)
                self.assertEqual(self.app.results, rows)
                self.assertEqual(target.read_bytes(), b'PREVIOUS REPORT')
                self.assertEqual(str(self.app.export_button['state']), 'normal')
                self.assertEqual(list(Path(self.temp.name).iterdir()), [target])

    def test_successful_retry_after_failed_start_uses_existing_demo_flow(self):
        cfg = self.app._snapshot('inspect')
        self.fail_start(lambda: self.app._begin(cfg, 'inspect'))
        self.app._begin(cfg, 'inspect')
        deadline = time.monotonic() + 5
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.005)
        self.assertFalse(self.app.busy)
        self.assertEqual([row.status for row in self.app.results], ['조회완료'] * len(cfg.ap_ips))
        self.app.worker.join(1)
        self.assertFalse(self.app.worker.is_alive())


    def test_resume_retry_requeries_ap_without_resending_applied_configuration(self):
        cfg = self.app._snapshot('apply')
        cfg.ap_ips = cfg.ap_ips[:1]
        cfg.ap_hostnames = {ip: name for ip, name in cfg.ap_hostnames.items() if ip in cfg.ap_ips}
        prior = [Result('2026-11-11T00:00:00+09:00', cfg.ap_ips[0], '확인불가',
                        mode='apply', simulated=True, config_sent=True, expected_nat='2',
                        before_ip='192.0.2.200', before_nat='2', attempts=1)]
        self.fail_start(lambda: self.app._begin(cfg, 'apply', prior))
        sent = []
        class AlreadyApplied(DemoSession):
            def connect(self, ap_ip):
                super().connect(ap_ip)
                self.ip, self.nat, self.key = self.config.server_ip, '2', self.config.shared_key
            def execute(self, command):
                sent.append(command)
                return super().execute(command)
        with patch('wec_wips.core.DemoSession', AlreadyApplied), \
             patch('wec_wips.gui.messagebox.askyesno', return_value=True):
            self.app._resume()
            deadline = time.monotonic() + 5
            while self.app.busy and time.monotonic() < deadline:
                self.root.update()
                time.sleep(0.005)
            self.assertFalse(self.app.busy)
            self.app.worker.join(1)
        self.assertEqual(sent, [SUMMARY_COMMAND])
        self.assertEqual(self.app.results[0].status, '이미일치')
        self.assertTrue(self.app.results[0].config_sent)
        self.assertEqual(self.app.results[0].expected_nat, '2')
        self.assertEqual(self.app.results[0].attempts, 2)


class SocketCancellationTests(unittest.TestCase):
    def run_cancel(self, mode):
        stop = threading.Event()
        captured = {}
        lines = []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(4)
        cfg = RunConfig('127.0.0.1', listener.getsockname()[1], 'operator', 'SyntheticCtlPW',
                        ['192.0.2.11', '192.0.2.12'], 50022, 'root', 'SyntheticApPW',
                        server_ip='192.0.2.99', shared_key='SyntheticTargetKey', timeout=2)
        def run():
            try:
                captured['results'] = Runner(cfg, lambda *_: None, lambda *_: True, stop).run(mode)
            except BaseException as exc:
                captured['error'] = type(exc).__name__
        worker = threading.Thread(target=run, name='test-cancellation-client')
        peer = None
        try:
            worker.start()
            peer, _ = listener.accept()
            peer.settimeout(4)
            def exchange(response, expected):
                peer.sendall(response.encode('utf-8'))
                value = bytearray()
                while not value.endswith(b'\n'):
                    chunk = peer.recv(1)
                    if not chunk:
                        self.fail('Client disconnected before cancellation point')
                    value.extend(chunk)
                line = value.rstrip(b'\r\n').decode('utf-8')
                lines.append(line)
                self.assertEqual(line, expected)
            exchange('Username:', cfg.controller_user)
            exchange('Password:', cfg.controller_password)
            exchange('WEC8500#', 'ssh 192.0.2.11 root 50022')
            exchange('Password:', cfg.ap_password)
            exchange('TEST_AP#', SUMMARY_COMMAND)
            if mode == 'apply':
                exchange('wips server ip : 192.0.2.10\r\nwips nat : 1\r\n'
                         'wips sharedkey : SyntheticOldKey\r\nTEST_AP#',
                         'config wips server 192.0.2.99 1 SyntheticTargetKey')
            # Cancel after a complete request, while the peer withholds its reply.
            stop.set()
            worker.join(3)
            self.assertFalse(worker.is_alive(), 'Cancellation must finish without another retry')
            self.assertNotIn('error', captured)
            self.assertEqual(peer.recv(1), b'', 'Client must close its actual TCP socket')
            rows = captured['results']
            self.assertEqual(rows[0].status, '확인불가' if mode == 'apply' else '중지')
            self.assertEqual(rows[0].config_sent, mode == 'apply')
            self.assertEqual(rows[0].error_code, 'CANCELLED')
            self.assertEqual(rows[1].status, '미실행')
            self.assertEqual(rows[0].attempts, 1)
            self.assertEqual(sum(line.startswith('config ') for line in lines), int(mode == 'apply'))
            self.assertFalse(any('192.0.2.12' in line for line in lines))
        finally:
            stop.set()
            if peer is not None:
                peer.close()
            listener.close()
            if worker.ident is not None:
                worker.join(5)

    def test_cancel_during_read_closes_socket_and_does_not_visit_next_ap(self):
        self.run_cancel('inspect')

    def test_cancel_after_write_retains_unknown_state_and_never_repeats_write(self):
        self.run_cancel('apply')


if __name__ == '__main__':
    unittest.main()
