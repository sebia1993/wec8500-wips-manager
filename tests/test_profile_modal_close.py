"""Real Tk modal-event-loop regressions; synthetic credentials and loopback only.

The standard askyesno dialog is NOT mocked. A Tk timer invokes its Yes/No
button after the profile worker finishes, while the application event pump
continues to run inside that native Tk dialog. This is not Windows GUI proof.
"""
from __future__ import annotations

import gc
import sys
from pathlib import Path
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from profile_test_support import drain_profile
from test_gui import destroy_test_root
from test_integration import _TelnetController
from test_profile_store import TokenProtector, settings
from wec_wips.profile_store import ProfileStore
from wec_wips.profile_ui import ProfileApp


@unittest.skipIf(sys.platform in ('win32', 'darwin'),
                     'X11 Tk dialog automation only; native OS dialogs require separate validation')
class ProfileModalCloseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = _TelnetController().__enter__()
        self.crypto = TokenProtector()
        self.store = ProfileStore(Path(self.temp.name) / 'settings', self.crypto)
        self.data = settings()
        self.data.update(controller_ip='127.0.0.1', controller_port=self.server.port,
                         ap_ips=['192.0.2.10'], ap_hostnames={'192.0.2.10': 'LAB'},
                         auto_recover=False, timeout=2)
        self.store.save(self.data, ap_password='APIntegrationSecret', shared_key='NewIntegrationKey')
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        drain_profile(self.app)
        self.app.controller_user.set('controlleradmin')
        self.app.controller_password.set('ControllerIntegrationSecret')
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name, 'LOCALAPPDATA': self.temp.name})
        self.env.start()
        self.release = threading.Event()
        self.callback_errors = []
        self.root.report_callback_exception = lambda *args: self.callback_errors.append(args[0].__name__)

    def exists(self):
        try:
            return bool(self.root.winfo_exists())
        except tk.TclError:
            return False

    def tearDown(self):
        try:
            self.release.set()
            self.app.stop_event.set()
            for worker in (self.app._profile_worker, self.app.worker):
                if worker is not None:
                    worker.join(5)
                    self.assertFalse(worker.is_alive())
            if self.exists():
                destroy_test_root(self.root)
            self.app = self.root = None
            gc.collect()
        finally:
            self.env.stop()
            self.server.__exit__(None, None, None)
            self.temp.cleanup()

    def invoke_dialog_button(self, choice):
        # Find the standard Tk dialog button; do not replace the modal wait.
        def walk(parent):
            for child in self.root.tk.splitlist(self.root.tk.call('winfo', 'children', parent)):
                if child.endswith('.' + choice):
                    self.root.tk.call(child, 'invoke')
                    return True
                if walk(child):
                    return True
            return False
        return walk('.')

    def close_while_worker_finishes(self, accept, during=None):
        worker = self.app._profile_worker
        observed = {}
        deadline = time.monotonic() + 4
        def answer():
            observed['connections_during_dialog'] = self.server.tcp_connections
            observed['busy_during_dialog'] = self.app._profile_busy
            observed['clicked'] = self.invoke_dialog_button('yes' if accept else 'no')
        def poll():
            if not worker.is_alive():
                # Give the ordinary 100ms pump a chance to run inside askyesno.
                self.root.after(250, answer)
            elif time.monotonic() < deadline:
                self.root.after(10, poll)
            else:
                observed['timeout'] = True
                self.invoke_dialog_button('no')
        self.release.set()
        if during is not None:
            self.root.after(20, during)
        self.root.after(10, poll)
        # Never leave an unattended native dialog hanging if a Tk theme changes
        # its button paths. This is a test timeout, not an application timeout.
        watchdog = self.root.after(5000, self.root.destroy)
        try:
            self.app._close()  # Real standard dialog, nested event loop until timer answers.
        finally:
            if self.exists():
                self.root.after_cancel(watchdog)
        self.assertNotIn('timeout', observed)
        self.assertTrue(observed.get('clicked'), 'Standard Tk dialog must receive its answer')
        return observed

    def wait_idle_or_closed(self):
        deadline = time.monotonic() + 8
        while self.exists() and self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(.005)
        self.assertFalse(self.app.busy)
        self.assertEqual(self.callback_errors, [])

    def exercise_preparation(self, accept, mode='inspect'):
        entered = threading.Event()
        original = self.crypto.unprotect
        def gated(*args):
            entered.set()
            if not self.release.wait(5):
                raise RuntimeError('test release timeout')
            return original(*args)
        with patch.object(self.crypto, 'unprotect', side_effect=gated):
            if mode == 'apply':
                self.root.after(20, lambda: self.invoke_dialog_button('yes'))
            self.app._start(mode)
            self.assertTrue(entered.wait(1))
            observed = self.close_while_worker_finishes(accept)
            self.wait_idle_or_closed()
        self.assertEqual(observed['connections_during_dialog'], 0,
                         'Controller connected before the close decision was resolved')
        self.assertTrue(observed['busy_during_dialog'], 'Completion must remain pending until the answer')
        if accept:
            self.assertEqual(self.server.tcp_connections, 0)
            self.assertEqual(self.server.commands, [])
            self.assertFalse(self.exists())
        else:
            self.assertTrue(self.exists())
            self.assertEqual(self.server.tcp_connections, 1)
            self.assertEqual([r.status for r in self.app.results], ['조회완료'])
            self.assertEqual(sum(cmd == 'show config wips summary' for _, cmd in self.server.commands), 1)
            self.assertFalse(any(cmd.startswith('config ') for _, cmd in self.server.commands))

    def test_accept_close_never_connects_when_preparation_finishes_inside_dialog(self):
        # Break caught: consuming preparation completion inside askyesno before Yes.
        self.exercise_preparation(True)

    def test_accept_close_drops_prepared_apply_without_connection_or_write(self):
        # Even after the earlier apply confirmation, a pending close decision
        # must prevent dispatch until resolved; Yes discards the prepared change.
        self.exercise_preparation(True, mode='apply')

    def test_decline_close_defers_connection_until_answer_then_queries_once(self):
        # Break caught: processing completion before the close decision, or losing No.
        self.exercise_preparation(False)


    def test_successful_save_finishing_inside_dialog_closes_only_after_yes(self):
        # Break caught: completing save before the decision leaves a late close
        # request stranded, so the promised automatic close never happens.
        entered = threading.Event()
        original = self.crypto.protect
        def gated(*args):
            entered.set()
            if not self.release.wait(5):
                raise RuntimeError('test release timeout')
            return original(*args)
        self.app.ap_password.set('UpdatedSyntheticAP')
        with patch.object(self.crypto, 'protect', side_effect=gated):
            self.app._save_profile_values(True, False, True)
            self.assertTrue(entered.wait(1))
            observed = self.close_while_worker_finishes(True)
            self.wait_idle_or_closed()
        self.assertTrue(observed['busy_during_dialog'])
        self.assertFalse(self.exists())
        self.assertEqual(self.server.tcp_connections, 0)
        profile = self.store.load()
        self.assertEqual(self.store.secret(profile, 'ap_password', self.data), 'UpdatedSyntheticAP')

    def test_failed_save_inside_close_dialog_remains_visible_after_yes(self):
        # Break caught: displaying the error inside the close dialog, then losing
        # the close state; a failed save must keep original bytes/manual input.
        entered = threading.Event()
        before = self.store.path.read_bytes()
        notices = []
        decision_returned = []
        def gated_failure(*args):
            entered.set()
            if not self.release.wait(5):
                raise RuntimeError('test release timeout')
            raise RuntimeError('SYNTHETIC_PRIVATE_EXCEPTION')
        def show_error(*args, **kwargs):
            notices.append((bool(decision_returned), str(args)))
        self.app.ap_password.set('UnsavedSyntheticAP')
        with patch.object(self.crypto, 'protect', side_effect=gated_failure), \
             patch('wec_wips.profile_ui.messagebox.showerror', side_effect=show_error):
            self.app._save_profile_values(True, False, True)
            self.assertTrue(entered.wait(1))
            observed = self.close_while_worker_finishes(True)
            decision_returned.append(True)
            self.wait_idle_or_closed()
        self.assertTrue(observed['busy_during_dialog'])
        self.assertTrue(self.exists())
        self.assertFalse(self.app._profile_close_requested)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_PROTECT_FAILED')
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(self.app.ap_password.get(), 'UnsavedSyntheticAP')
        self.assertEqual(len(notices), 1)
        self.assertTrue(notices[0][0], 'Error notice must follow, not nest inside, the close decision')
        self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION', notices[0][1])
        self.assertEqual(self.server.tcp_connections, 0)

    def test_repeated_close_while_dialog_open_does_not_nest_or_start_early(self):
        # Break caught: allowing another close callback to create a second modal
        # decision while the first decision still owns the pending completion.
        from tkinter import messagebox
        entered = threading.Event()
        original = self.crypto.unprotect
        original_ask = messagebox.askyesno
        def gated(*args):
            entered.set()
            if not self.release.wait(5):
                raise RuntimeError('test release timeout')
            return original(*args)
        with patch.object(self.crypto, 'unprotect', side_effect=gated), \
             patch('wec_wips.profile_ui.messagebox.askyesno', wraps=original_ask) as ask:
            self.app._start('inspect')
            self.assertTrue(entered.wait(1))
            observed = self.close_while_worker_finishes(True, during=self.app._close)
            self.wait_idle_or_closed()
        self.assertEqual(ask.call_count, 1)
        self.assertEqual(observed['connections_during_dialog'], 0)
        self.assertEqual(self.server.tcp_connections, 0)
        self.assertFalse(self.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
