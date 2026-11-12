"""Exercise real save-dialog controls, not a substituted save callback.

Synthetic values, temporary files and loopback transport only. TokenProtector
is a test double at the OS-protection boundary, not native Windows encryption.
"""
from __future__ import annotations

import gc
import json
from pathlib import Path
import tempfile
import time
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch

from profile_test_support import drain_profile
from test_gui import destroy_test_root
from test_integration import _TelnetController
from test_profile_store import TokenProtector
from wec_wips.profile_store import ProfileStore
from wec_wips.profile_ui import ProfileApp


class ProfileSaveDialogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = _TelnetController().__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)
        self.crypto = TokenProtector()
        self.store = ProfileStore(Path(self.temp.name) / 'settings', self.crypto)
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name,
                                            'LOCALAPPDATA': self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        self.addCleanup(self.close_window)
        self.callback_errors = []
        self.root.report_callback_exception = lambda *args: self.callback_errors.append(args[0].__name__)
        drain_profile(self.app)
        self.fill_form()

    def close_window(self):
        self.app.stop_event.set()
        drain_profile(self.app)
        for worker in (self.app._profile_worker, self.app.worker):
            if worker is not None:
                worker.join(5)
                self.assertFalse(worker.is_alive())
        destroy_test_root(self.root)
        self.app = self.root = None
        gc.collect()

    def fill_form(self):
        for variable, value in (
            (self.app.controller_ip, '127.0.0.1'), (self.app.controller_port, str(self.server.port)),
            (self.app.controller_user, 'controlleradmin'),
            (self.app.controller_password, 'ControllerIntegrationSecret'),
            (self.app.ap_user, 'root'), (self.app.ap_port, '50022'),
            (self.app.ap_password, 'APIntegrationSecret'),
            (self.app.server_ip, '198.51.100.20'), (self.app.shared_key, 'NewIntegrationKey'),
            (self.app.timeout, '2'),
        ):
            variable.set(value)
        self.app.demo.set(False)
        self.app.auto_recover.set(False)
        self.app.ap_text.delete('1.0', 'end')
        self.app.ap_text.insert('1.0', '192.0.2.10')
        self.app.ap_hostnames = {'192.0.2.10': 'CSV-LAB'}

    @staticmethod
    def descendants(parent):
        for child in parent.winfo_children():
            yield child
            yield from ProfileSaveDialogTests.descendants(child)

    def open_dialog(self):
        self.app.profile_save_button.invoke()
        self.root.update()
        dialogs = [child for child in self.root.winfo_children()
                   if isinstance(child, tk.Toplevel)]
        self.assertEqual(len(dialogs), 1)
        return dialogs[0]

    def control(self, dialog, kind, text_prefix):
        matches = [widget for widget in self.descendants(dialog)
                   if isinstance(widget, kind) and str(widget.cget('text')).startswith(text_prefix)]
        self.assertEqual(len(matches), 1, text_prefix)
        return matches[0]

    def choose(self, dialog, *, ap=False, key=False, targets=False):
        for prefix, desired in (('AP 비밀번호를', ap), ('변경 목표 WIPS', key), ('AP IP 목록', targets)):
            checkbox = self.control(dialog, ttk.Checkbutton, prefix)
            current = bool(self.root.getboolean(self.root.getvar(checkbox.cget('variable'))))
            if current != desired:
                checkbox.invoke()

    def submit(self, dialog):
        self.control(dialog, ttk.Button, '선택한 항목 저장').invoke()
        drain_profile(self.app)
        self.assertFalse(self.app.busy)
        self.assertEqual(self.callback_errors, [])

    def save_selected(self, *, ap=False, key=False, targets=False):
        dialog = self.open_dialog()
        self.choose(dialog, ap=ap, key=key, targets=targets)
        self.submit(dialog)
        self.assertEqual(self.app._last_profile_error, '')
        self.assertIsNone(self.root.grab_current())

    def assert_no_device_operation(self):
        self.assertIsNone(self.app.worker)
        self.assertEqual(self.server.tcp_connections, 0)
        self.assertEqual(self.server.commands, [])

    def assert_no_plaintext_on_disk(self):
        for path in Path(self.temp.name).rglob('*'):
            if path.is_file():
                raw = path.read_bytes()
                for value in (b'ControllerIntegrationSecret', b'APIntegrationSecret', b'NewIntegrationKey'):
                    self.assertNotIn(value, raw, path.name)

    def test_first_save_without_opt_in_does_not_persist_typed_secrets_or_targets(self):
        # Detects a dialog default accidentally opting in, or handler serializing
        # the whole form irrespective of the consent checkboxes.
        dialog = self.open_dialog()
        self.submit(dialog)  # Do not change the first-use checkbox values.
        saved = json.loads(self.store.path.read_bytes())
        self.assertEqual(saved['secrets'], {})
        self.assertEqual(saved['settings']['ap_ips'], [])
        self.assertEqual(saved['settings']['ap_hostnames'], {})
        self.assertNotIn('controller_user', saved['settings'])
        self.assertNotIn('controller_password', saved['settings'])
        self.assert_no_plaintext_on_disk()
        self.assert_no_device_operation()

    def test_cancel_escape_and_window_close_do_not_commit_changed_choices(self):
        # Detects any dismiss path saving selections that the user did not submit.
        self.save_selected(ap=True, key=True, targets=True)
        before = self.store.path.read_bytes()
        for dismissal in ('cancel', 'escape', 'window_close'):
            with self.subTest(dismissal=dismissal):
                dialog = self.open_dialog()
                self.choose(dialog)  # Deselect everything but do not approve saving.
                if dismissal == 'cancel':
                    self.control(dialog, ttk.Button, '취소').invoke()
                elif dismissal == 'escape':
                    dialog.focus_force()
                    self.root.update()
                    dialog.event_generate('<Escape>')
                else:
                    self.root.tk.call(dialog.protocol('WM_DELETE_WINDOW'))
                self.root.update()
                drain_profile(self.app)
                self.assertFalse(dialog.winfo_exists())
                self.assertEqual(self.store.path.read_bytes(), before)
                self.assertIsNone(self.root.grab_current())
                self.assert_no_device_operation()
        self.assertEqual(self.callback_errors, [])

    def test_checkbox_choices_store_only_ap_password_then_remove_it_on_next_save(self):
        # Detects swapped/ignored checkbutton variables and failure to remove an
        # explicitly deselected secret while retaining another selected field.
        self.save_selected(ap=True, targets=True)
        stored = self.store.load()
        self.assertEqual(set(stored.secrets), {'ap_password'})
        self.assertEqual(stored.settings['ap_ips'], ['192.0.2.10'])
        self.assertEqual(self.store.secret(stored, 'ap_password', stored.settings), 'APIntegrationSecret')
        self.save_selected(key=True)
        stored = self.store.load()
        self.assertEqual(set(stored.secrets), {'shared_key'})
        self.assertEqual(stored.settings['ap_ips'], [])
        self.assertEqual(self.store.secret(stored, 'shared_key', stored.settings), 'NewIntegrationKey')
        self.assert_no_plaintext_on_disk()
        self.assert_no_device_operation()

    def test_invalid_input_keeps_dialog_and_allows_correction_without_partial_save(self):
        # Detects destroying the dialog/committing after validation failure or
        # leaving a grab/disabled button that prevents correcting the input.
        self.app.controller_port.set('not-a-port')
        dialog = self.open_dialog()
        self.choose(dialog, ap=True, targets=True)
        # Error rendering is external presentation; keep validation/save real.
        with patch('wec_wips.profile_ui.messagebox.showerror'):
            self.control(dialog, ttk.Button, '선택한 항목 저장').invoke()
        self.assertTrue(dialog.winfo_exists())
        self.assertFalse(self.store.path.exists())
        self.assertFalse(self.app.busy)
        self.assert_no_device_operation()
        self.app.controller_port.set(str(self.server.port))
        self.submit(dialog)
        self.assertFalse(dialog.winfo_exists())
        self.assertIsNone(self.root.grab_current())
        stored = self.store.load()
        self.assertEqual(set(stored.secrets), {'ap_password'})
        self.assertEqual(stored.settings['controller_port'], self.server.port)
        self.assert_no_plaintext_on_disk()

    def test_newer_profile_saved_while_dialog_is_open_is_not_overwritten(self):
        # Detects a UI save that uses an unconditional revision, despite storage
        # level conflict protection working when called directly.
        self.save_selected(ap=True, key=True, targets=True)
        dialog = self.open_dialog()
        other = ProfileStore(self.store.directory, self.crypto)
        current = other.load()
        other.save(current.settings, ap_password='RotatedSyntheticAP', shared_key='RotatedSyntheticKey')
        newer = self.store.path.read_bytes()
        with patch('wec_wips.profile_ui.messagebox.showerror'):
            self.submit(dialog)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_CHANGED')
        self.assertEqual(self.store.path.read_bytes(), newer)
        current = other.load()
        self.assertEqual(other.secret(current, 'ap_password', current.settings), 'RotatedSyntheticAP')
        self.assert_no_device_operation()

    def test_dialog_save_reopen_and_user_login_perform_one_query_without_autostart(self):
        # Detects dialog wiring storing the wrong values, startup reusing WEC
        # credentials, or ordinary save/load silently initiating a device task.
        self.save_selected(ap=True, targets=True)
        original = self.store.path.read_bytes()
        destroy_test_root(self.root)
        self.app = self.root = None
        gc.collect()
        self.store = ProfileStore(self.store.directory, self.crypto)
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        drain_profile(self.app)
        self.assertEqual(self.app.controller_user.get(), '')
        self.assertEqual(self.app.controller_password.get(), '')
        self.assertEqual(self.app.ap_password.get(), '')
        self.assertEqual(self.app.ap_text.get('1.0', 'end').strip(), '192.0.2.10')
        self.assert_no_device_operation()
        self.app.controller_user.set('controlleradmin')
        self.app.controller_password.set('ControllerIntegrationSecret')
        self.app.inspect_button.invoke()
        deadline = time.monotonic() + 8
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)
        self.assertFalse(self.app.busy)
        self.assertIsNotNone(self.app.worker)
        self.app.worker.join(2)
        self.assertFalse(self.app.worker.is_alive())
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertEqual([row.status for row in self.app.results], ['조회완료'])
        self.assertEqual([row.ap_ip for row in self.app.results], ['192.0.2.10'])
        commands = [command for _, command in self.server.commands]
        self.assertEqual(commands.count('show config wips summary'), 1)
        self.assertFalse(any(command.startswith('config ') for command in commands))
        self.assertEqual(self.server.errors, [])
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assert_no_plaintext_on_disk()


if __name__ == '__main__':
    unittest.main(verbosity=2)
