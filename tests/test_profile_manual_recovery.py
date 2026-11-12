"""Manual recovery after protected-profile failures, with real Tk/Runner/TCP.

All secrets are synthetic. Protection is a test double; native Windows DPAPI
and hardware remain outside this suite. Faults are injected at storage/crypto
boundaries, not by replacing the device Runner or producing fake AP results.
"""
from __future__ import annotations

import base64
import gc
import json
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from profile_test_support import drain_profile
from test_gui import destroy_test_root
from test_integration import _TelnetController
from test_profile_store import TokenProtector, settings
from wec_wips.profile_store import ProfileError, ProfileStore
from wec_wips.profile_ui import ProfileApp


class ProfileManualRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = _TelnetController().__enter__()
        self.crypto = TokenProtector()
        self.store = ProfileStore(Path(self.temp.name) / 'settings', self.crypto)
        self.data = settings()
        self.data.update(controller_ip='127.0.0.1', controller_port=self.server.port,
                         ap_ips=['192.0.2.10'], ap_hostnames={'192.0.2.10': 'CSV-LAB'},
                         auto_recover=False, timeout=2)
        self.store.save(self.data, ap_password='APIntegrationSecret',
                        shared_key='NewIntegrationKey')
        self.root = None
        self.app = None
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name,
                                             'LOCALAPPDATA': self.temp.name})
        self.env.start()
        # Error dialogs are external presentation, not the behavior under test.
        # Real state, persistent bytes and TCP side effects are asserted below.
        self.error_patch = patch('wec_wips.profile_ui.messagebox.showerror')
        self.error = self.error_patch.start()

    def new_window(self):
        if self.root is not None:
            drain_profile(self.app)
            destroy_test_root(self.root)
            self.app = self.root = None
            gc.collect()
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        drain_profile(self.app)

    def manual_settings(self):
        self.app.demo.set(False)
        self.app.controller_ip.set('127.0.0.1')
        self.app.controller_port.set(str(self.server.port))
        self.app.ap_user.set('root')
        self.app.ap_port.set('50022')
        self.app.timeout.set('2')
        self.app.auto_recover.set(False)
        self.app.server_ip.set('198.51.100.20')
        self.app.ap_text.delete('1.0', 'end')
        self.app.ap_text.insert('1.0', '192.0.2.10')
        self.app.ap_password.set('APIntegrationSecret')
        self.login()

    def login(self):
        self.app.controller_user.set('controlleradmin')
        self.app.controller_password.set('ControllerIntegrationSecret')

    def inspect(self):
        self.app._start('inspect')
        deadline = time.monotonic() + 8
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)
        self.assertFalse(self.app.busy, 'Manual recovery left the application busy')
        self.assertIsNotNone(self.app.worker, 'Device worker was never started')
        self.app.worker.join(2)
        self.assertFalse(self.app.worker.is_alive())
        self.assertEqual([row.status for row in self.app.results], ['조회완료'])
        self.assertEqual(self.app.results[0].ap_ip, '192.0.2.10')
        self.assertEqual(self.app.results[0].controller_return, '복귀확인')
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertEqual(sum(cmd == 'show config wips summary'
                             for _, cmd in self.server.commands), 1)
        self.assertFalse(any(cmd.startswith('config ') for _, cmd in self.server.commands))
        self.assertEqual(self.server.errors, [])

    def assert_idle_without_connection(self):
        self.assertFalse(self.app.busy)
        self.assertIsNone(self.app.worker)
        self.assertEqual(self.server.tcp_connections, 0)
        self.assertEqual(self.server.commands, [])

    def tearDown(self):
        try:
            if self.app is not None:
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
            self.error_patch.stop()
            self.env.stop()
            self.server.__exit__(None, None, None)
            self.temp.cleanup()

    def test_corrupt_startup_allows_explicit_manual_query_without_rewriting_file(self):
        # Break caught: treating any saved-file error as mandatory app failure,
        # or silently replacing corrupt saved data on a manual device operation.
        raw = b'{"schema":1,"settings":'
        self.store.path.write_bytes(raw)
        self.new_window()
        self.assertEqual(self.app._last_profile_error, 'PROFILE_FORMAT_INVALID')
        self.assertIsNone(self.app._profile)
        self.assert_idle_without_connection()
        self.manual_settings()
        with patch.object(self.crypto, 'unprotect',
                          side_effect=RuntimeError('No saved secret is usable here')):
            self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)

    def test_failed_reload_discards_cached_secrets_but_allows_manual_query(self):
        # Break caught: a failed reload leaves previously cached credentials
        # selected, or manual operation is coupled to the failing file read.
        self.new_window()
        raw = self.store.path.read_bytes()
        with patch.object(self.store, '_read_raw',
                          side_effect=ProfileError(code='PROFILE_ACCESS_DENIED')):
            self.app._load_profile(silent=True)
            drain_profile(self.app)
            self.assertEqual(self.app._last_profile_error, 'PROFILE_ACCESS_DENIED')
            self.assertIsNone(self.app._profile)
            self.assertFalse(self.app.use_saved_ap.get())
            self.assertFalse(self.app.use_saved_key.get())
            self.assert_idle_without_connection()
            self.manual_settings()
            self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)

    def test_decrypt_failure_then_manual_password_queries_without_saving_new_value(self):
        # Break caught: failed decryption starts a device connection, or manual
        # replacement still requires saved-secret decryption / silently persists.
        self.new_window()
        self.login()
        raw = self.store.path.read_bytes()
        with patch.object(self.crypto, 'unprotect',
                          side_effect=RuntimeError('SYNTHETIC_PRIVATE_DECRYPT_DETAIL')):
            self.app._start('inspect')
            drain_profile(self.app)
            self.assertEqual(self.app._last_profile_error, 'PROFILE_DECRYPT_FAILED')
            self.assert_idle_without_connection()
            self.app.ap_password.set('APIntegrationSecret')
            self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)
        self.assertNotIn('SYNTHETIC_PRIVATE_DECRYPT_DETAIL', str(self.error.call_args_list))

    def test_unusable_target_key_does_not_block_query_but_cannot_authorize_apply(self):
        # Break caught: query decrypts a key it does not need, or apply falls
        # back to an unverified key when target-key decryption fails.
        saved = json.loads(self.store.path.read_bytes())
        key_token = base64.b64decode(saved['secrets']['shared_key'])
        del self.crypto.values[key_token]
        raw = self.store.path.read_bytes()
        self.new_window()
        self.login()
        self.inspect()
        prior = self.app.results[:]
        with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._start('apply')
            drain_profile(self.app)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_DECRYPT_FAILED')
        self.assertEqual(self.app.results, prior)
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertFalse(any(cmd.startswith('config ') for _, cmd in self.server.commands))
        self.assertEqual(self.store.path.read_bytes(), raw)

    def test_deselecting_secrets_survives_reopen_and_requires_manual_ap_password(self):
        # Break caught: deselection saves old ciphertext, or reopening revives
        # secret use despite empty selected-secret storage.
        self.new_window()
        self.app._save_profile_values(False, False, True)
        drain_profile(self.app)
        self.assertEqual(json.loads(self.store.path.read_bytes())['secrets'], {})
        raw = self.store.path.read_bytes()
        self.new_window()
        self.login()
        self.assertFalse(self.app.use_saved_ap.get())
        self.assertFalse(self.app.use_saved_key.get())
        self.app._start('inspect')
        self.assert_idle_without_connection()
        self.app.ap_password.set('APIntegrationSecret')
        with patch.object(self.crypto, 'unprotect', side_effect=RuntimeError('No ciphertext selected')):
            self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)

    def test_explicit_delete_and_resave_recovers_from_corrupt_profile(self):
        # Break caught: corruption cannot be deliberately reset using the
        # loaded revision, or reset accidentally persists controller credentials.
        self.store.path.write_bytes(b'{broken profile')
        self.new_window()
        with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._delete_profile()
            drain_profile(self.app)
        self.assertFalse(self.store.path.exists())
        self.manual_settings()
        self.app._save_profile_values(True, False, True)
        drain_profile(self.app)
        doc = json.loads(self.store.path.read_bytes())
        self.assertEqual(set(doc['secrets']), {'ap_password'})
        self.assertNotIn('controller_user', doc['settings'])
        self.assertNotIn('controller_password', doc['settings'])
        self.assertNotIn(b'APIntegrationSecret', self.store.path.read_bytes())
        self.assertNotIn(b'ControllerIntegrationSecret', self.store.path.read_bytes())
        self.new_window()
        self.assertEqual(self.app.controller_user.get(), '')
        self.assertEqual(self.app.controller_password.get(), '')
        self.login()
        self.inspect()

    def test_failed_delete_preserves_profile_for_subsequent_saved_password_query(self):
        # Break caught: failed deletion is treated as successful in memory and
        # destroys usable stored secret selection despite preserving disk bytes.
        self.new_window()
        self.login()
        raw = self.store.path.read_bytes()
        with patch('wec_wips.profile_store.Path.unlink',
                   side_effect=PermissionError('SYNTHETIC_PRIVATE_PATH')), \
             patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._delete_profile()
            drain_profile(self.app)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_ACCESS_DENIED')
        self.assertTrue(self.app.use_saved_ap.get())
        self.assert_idle_without_connection()
        self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)
        self.assertNotIn('SYNTHETIC_PRIVATE_PATH', str(self.error.call_args_list))

    def test_omitted_targets_cannot_start_until_operator_supplies_ap_list(self):
        # Break caught: profile restoration silently reuses a previous AP list
        # or dispatches before the operator supplies valid targets.
        self.new_window()
        self.app._save_profile_values(True, True, False)
        drain_profile(self.app)
        raw = self.store.path.read_bytes()
        self.new_window()
        self.login()
        self.assertEqual(self.app.ap_text.get('1.0', 'end').strip(), '')
        self.assertEqual(self.app.ap_hostnames, {})
        self.app._start('inspect')
        self.assert_idle_without_connection()
        self.app.ap_text.insert('1.0', '192.0.2.10')
        self.inspect()
        self.assertEqual(self.store.path.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
