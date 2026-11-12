"""Profile form updates must not publish mixed old/new connection inputs.

Use real Tk/store/Runner and a loopback controller. Only a widget write is
failed deliberately; there is no native Windows or real equipment claim.
"""
from __future__ import annotations

import copy
import gc
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from profile_test_support import drain_profile, resolved_snapshot
from test_gui import destroy_test_root
from test_integration import _TelnetController
from test_profile_store import TokenProtector, settings
from wec_wips.core import Result
from wec_wips.profile_store import ProfileStore
from wec_wips.profile_ui import ProfileApp


class ProfileLoadCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = _TelnetController().__enter__()
        self.crypto = TokenProtector()
        self.store = ProfileStore(Path(self.temp.name) / 'settings', self.crypto)
        old = settings()
        old.update(ap_ips=['192.0.2.10'], ap_hostnames={'192.0.2.10': 'OLD-AP'},
                   auto_recover=False, timeout=2)
        self.store.save(old, ap_password='APIntegrationSecret', shared_key='NewIntegrationKey')
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        drain_profile(self.app)
        self.login()
        # These manually entered credentials must not survive switching targets.
        self.app.ap_password.set('APIntegrationSecret')
        self.app.shared_key.set('NewIntegrationKey')
        self.saved_config = resolved_snapshot(self.app, 'apply')
        self.app.saved_config = copy.deepcopy(self.saved_config)
        self.app.saved_mode = 'apply'
        self.previous = [Result('2026-11-12', '192.0.2.10', '확인불가', mode='apply',
                                config_sent=True, expected_nat='2', attempts=2)]
        self.app.results = copy.deepcopy(self.previous)
        newer = settings()
        newer.update(controller_ip='127.0.0.1', controller_port=self.server.port,
                     ap_ips=['192.0.2.11'], ap_hostnames={'192.0.2.11': 'NEW-AP'},
                     auto_recover=False, timeout=2)
        other = ProfileStore(self.store.directory, self.crypto)
        other.load()
        other.save(newer, ap_password='APIntegrationSecret', shared_key='NewIntegrationKey')
        self.disk_before = self.store.path.read_bytes()
        self.errors = patch('wec_wips.profile_ui.messagebox.showerror')
        self.notice = self.errors.start()
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name,
                                           'LOCALAPPDATA': self.temp.name})
        self.env.start()

    def login(self):
        self.app.controller_user.set('controlleradmin')
        self.app.controller_password.set('ControllerIntegrationSecret')

    def fail_load_at(self, obj, method):
        # Simulate one Tcl update failure after a valid profile was read. The
        # actual load worker, completion queue and other widget writes run.
        with patch.object(obj, method, side_effect=tk.TclError('SYNTHETIC_PRIVATE_WIDGET_ERROR')):
            self.app._load_profile()
            drain_profile(self.app)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_WORKER_FAILED')
        self.assertFalse(self.app.busy)
        self.assertEqual(self.store.path.read_bytes(), self.disk_before)
        self.assertNotIn('SYNTHETIC_PRIVATE_WIDGET_ERROR', self.app.profile_status.get())

    def assert_unpublished_and_blank_secrets(self):
        self.assertIsNone(self.app._profile, 'Partly applied profile must not be usable')
        self.assertFalse(self.app.use_saved_ap.get())
        self.assertFalse(self.app.use_saved_key.get())
        self.assertEqual(self.app.controller_user.get(), '')
        self.assertEqual(self.app.controller_password.get(), '')
        self.assertEqual(self.app.ap_password.get(), '')
        self.assertEqual(self.app.shared_key.get(), '')
        self.assertEqual(self.app.results, self.previous)
        self.assertEqual(self.app.saved_config, self.saved_config)
        self.assertFalse(self.app._loading_profile)

    def wait_idle(self):
        deadline = time.monotonic() + 8
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)
        self.assertFalse(self.app.busy)
        if self.app.worker is not None:
            self.app.worker.join(3)
            self.assertFalse(self.app.worker.is_alive())

    def tearDown(self):
        try:
            self.app.stop_event.set()
            drain_profile(self.app)
            for worker in (self.app._profile_worker, self.app.worker):
                if worker is not None:
                    worker.join(5)
                    self.assertFalse(worker.is_alive())
            destroy_test_root(self.root)
            self.app = self.root = None
            gc.collect()
        finally:
            self.errors.stop()
            self.env.stop()
            self.server.__exit__(None, None, None)
            self.temp.cleanup()

    def test_partial_endpoint_update_cannot_connect_using_old_credentials_and_targets(self):
        # Break caught: failed load publishes its profile before the form is
        # complete; old secrets/list then work against a newly loaded endpoint.
        self.fail_load_at(self.app.ap_port, 'set')
        with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._start('inspect')
            self.wait_idle()
        self.assertEqual(self.server.tcp_connections, 0,
                         'Mixed old credentials/targets reached the newly loaded controller')
        self.assertEqual(self.server.commands, [])
        self.assert_unpublished_and_blank_secrets()

    def test_target_list_update_failure_does_not_publish_saved_secret_selection(self):
        self.fail_load_at(self.app.ap_text, 'insert')
        self.assert_unpublished_and_blank_secrets()
        self.assertEqual(self.app.ap_text.get('1.0', 'end').strip(), '')
        self.assertEqual(self.server.tcp_connections, 0)

    def test_late_form_failure_leaves_profile_unpublished_and_prior_results_intact(self):
        self.fail_load_at(self.app.demo, 'set')
        self.assert_unpublished_and_blank_secrets()
        self.assertEqual(self.server.tcp_connections, 0)

    def test_retry_after_form_failure_applies_new_target_and_queries_once(self):
        self.fail_load_at(self.app.ap_port, 'set')
        self.app._load_profile()
        drain_profile(self.app)
        self.assertEqual(self.app.controller_user.get(), '')
        self.assertEqual(self.app.controller_password.get(), '')
        self.assertEqual(self.app.ap_password.get(), '')
        self.assertEqual(self.app.ap_text.get('1.0', 'end').strip(), '192.0.2.11')
        self.assertEqual(self.app.ap_hostnames, {'192.0.2.11': 'NEW-AP'})
        self.login()
        with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._start('inspect')
            self.wait_idle()
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertEqual([r.ap_ip for r in self.app.results], ['192.0.2.11'])
        self.assertEqual([r.status for r in self.app.results], ['조회완료'])
        commands = [line for _, line in self.server.commands]
        self.assertIn('ssh 192.0.2.11 root 50022', commands)
        self.assertNotIn('ssh 192.0.2.10 root 50022', commands)
        self.assertFalse(any(line.startswith('config ') for line in commands))
        self.assertEqual(self.store.path.read_bytes(), self.disk_before)
        self.assertEqual(self.server.errors, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
