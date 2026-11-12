"""Interruption/lifecycle assurance for profile.2; no real device credentials.

Tests exercise existing code. TokenProtector is not an encryption algorithm.
Child-process interruption is tested on the host OS, not claimed as Win32 proof.
"""
from __future__ import annotations

import copy
import errno
import gc
import json
from pathlib import Path
import subprocess
import sys
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
from wec_wips.core import Result
from wec_wips.profile_lock import exclusive_profile_lock
from wec_wips.profile_store import ProfileError, ProfileStore
from wec_wips.profile_ui import ProfileApp

ROOT = Path(__file__).resolve().parents[1]


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(.005)
    if not predicate():
        raise AssertionError('Test precondition was not reached')


class PersistenceInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.crypto = TokenProtector()
        self.store = ProfileStore(self.path / 'settings', self.crypto)
        self.store.save(settings(), ap_password='ExistingSyntheticAP', shared_key='ExistingSyntheticKey')

    def child_at_boundary(self, script):
        ready = self.path / 'ready'
        process = subprocess.Popen(
            [sys.executable, '-u', '-c', script, str(ROOT), str(self.store.directory), str(ready)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def reap():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
        self.addCleanup(reap)
        wait_for(lambda: ready.exists() or process.poll() is not None)
        if not ready.exists():
            out, error = process.communicate(timeout=5)
            self.fail(f'Child did not reach boundary: {out} {error}')
        return process

    def test_terminated_lock_holder_does_not_leave_profile_permanently_busy(self):
        # Catches replacing the OS lock with an uncleared PID/sentinel lock.
        child = self.child_at_boundary('''
import sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from wec_wips.profile_lock import exclusive_profile_lock
with exclusive_profile_lock(Path(sys.argv[2])):
    Path(sys.argv[3]).touch()
    while True: time.sleep(.1)
''')
        original = self.store.path.read_bytes()
        with self.assertRaises(ProfileError) as error:
            self.store.save(settings())
        self.assertEqual(error.exception.code, 'PROFILE_BUSY')
        self.assertEqual(self.store.path.read_bytes(), original)
        child.kill(); child.communicate(timeout=5)
        self.store.save(settings(), ap_password='AfterExitSynthetic')
        current = self.store.load()
        self.assertEqual(self.store.secret(current, 'ap_password', settings()), 'AfterExitSynthetic')

    def test_process_death_before_publish_preserves_complete_previous_profile(self):
        # Catches writing directly into the live profile before a successful commit.
        original = self.store.path.read_bytes()
        child = self.child_at_boundary('''
import sys,time
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tests')]
from test_profile_store import TokenProtector
from wec_wips.profile_store import ProfileStore
s=ProfileStore(Path(sys.argv[2]),TokenProtector());p=s.load()
def boundary(src,dst):
    Path(sys.argv[3]).touch()
    while True: time.sleep(.1)
with patch('wec_wips.profile_store.os.replace',side_effect=boundary):
    s.save(p.settings,ap_password='InterruptedSyntheticAP',shared_key='InterruptedSyntheticKey')
''')
        self.assertEqual(self.store.path.read_bytes(), original)
        staged = list(self.store.directory.glob('.profile-*.tmp'))
        self.assertEqual(len(staged), 1)
        partial = staged[0].read_bytes()
        # Staging contains a complete encrypted envelope, never raw credentials.
        self.assertEqual(set(json.loads(partial)), {'schema', 'settings', 'secrets'})
        self.assertNotIn(b'InterruptedSyntheticAP', partial)
        self.assertNotIn(b'InterruptedSyntheticKey', partial)
        child.kill(); child.communicate(timeout=5)
        reloaded = self.store.load()
        self.assertEqual(self.store.secret(reloaded, 'ap_password', settings()), 'ExistingSyntheticAP')
        self.assertEqual(self.store.path.read_bytes(), original)
        self.store.save(settings(), ap_password='AfterCrashSynthetic')
        self.assertEqual(self.store.secret(self.store.load(), 'ap_password', settings()), 'AfterCrashSynthetic')

    def test_fsync_failure_does_not_publish_or_retain_incomplete_staging(self):
        # Catches ignoring a durable-write failure before replacing the old file.
        before = self.store.path.read_bytes()
        with patch('wec_wips.profile_store.os.fsync', side_effect=OSError(errno.ENOSPC, 'PRIVATE_DISK_CONTEXT')):
            with self.assertRaises(ProfileError) as error:
                self.store.save(settings(), ap_password='UnsavedSynthetic')
        self.assertEqual(error.exception.code, 'PROFILE_WRITE_FAILED')
        self.assertNotIn('PRIVATE_DISK_CONTEXT', str(error.exception))
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual(list(self.store.directory.glob('.profile-*.tmp')), [])
        self.assertEqual(self.store.secret(self.store.load(), 'ap_password', settings()), 'ExistingSyntheticAP')

    def test_swapped_ciphertext_kinds_are_rejected_without_rewriting_profile(self):
        # Catches removal of both kind-specific entropy and payload checks.
        doc = json.loads(self.store.path.read_bytes())
        doc['secrets']['ap_password'], doc['secrets']['shared_key'] = (
            doc['secrets']['shared_key'], doc['secrets']['ap_password'])
        raw = json.dumps(doc).encode()
        self.store.path.write_bytes(raw)
        profile = self.store.load()
        for kind in ('ap_password', 'shared_key'):
            with self.subTest(kind=kind), self.assertRaises(ProfileError) as error:
                self.store.secret(profile, kind, settings())
            self.assertEqual(error.exception.code, 'PROFILE_DECRYPT_FAILED')
        self.assertEqual(self.store.path.read_bytes(), raw)

    def test_window_that_observed_absence_cannot_delete_newly_created_profile(self):
        # Catches interpreting expected=None as unconditional delete permission.
        directory = self.path / 'initially-empty'
        old = ProfileStore(directory, self.crypto)
        self.assertIsNone(old.load())
        other = ProfileStore(directory, self.crypto)
        other.save(settings(), ap_password='CreatedElsewhereSynthetic')
        raw = other.path.read_bytes()
        with self.assertRaises(ProfileError) as error:
            old.delete()
        self.assertEqual(error.exception.code, 'PROFILE_CHANGED')
        self.assertEqual(other.path.read_bytes(), raw)


class PreparedConnectionAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.server = _TelnetController().__enter__()
        self.crypto = TokenProtector()
        self.store = ProfileStore(self.folder / 'settings', self.crypto)
        data = settings()
        data.update(controller_ip='127.0.0.1', controller_port=self.server.port,
                    ap_ips=['192.0.2.10'], ap_hostnames={'192.0.2.10': 'LAB-CSV'},
                    auto_recover=False, timeout=2)
        self.data = data
        self.store.save(data, ap_password='APIntegrationSecret', shared_key='NewIntegrationKey')
        self.root = tk.Tk()
        self.app = ProfileApp(self.root, store=self.store)
        drain_profile(self.app)
        self.app.controller_user.set('controlleradmin')
        self.app.controller_password.set('ControllerIntegrationSecret')
        self.errors = patch('wec_wips.profile_ui.messagebox.showerror')
        self.error = self.errors.start()
        self.env = patch.dict('os.environ', {'XDG_STATE_HOME': self.temp.name, 'LOCALAPPDATA': self.temp.name})
        self.env.start()

    def tearDown(self):
        try:
            self.app.stop_event.set()
            drain_profile(self.app)
            worker = self.app.worker
            if worker is not None and worker.is_alive():
                worker.join(5)
                self.assertFalse(worker.is_alive())
            destroy_test_root(self.root)
            self.app = self.root = None
            gc.collect()
        finally:
            self.errors.stop(); self.env.stop()
            self.server.__exit__(None, None, None)
            self.temp.cleanup()

    def other(self):
        value = ProfileStore(self.store.directory, self.crypto)
        value.load()
        return value

    def preserve_prior(self):
        rows = [Result('2026-11-12', '192.0.2.10', '확인불가', mode='apply',
                       config_sent=True, expected_nat='2', attempts=2)]
        self.app.results = copy.deepcopy(rows)
        return rows

    def assert_no_connection(self):
        self.assertIsNone(self.app.worker)
        self.assertEqual(self.server.tcp_connections, 0)
        self.assertEqual(self.server.commands, [])

    def change_during_prepare(self, delete):
        # Catches letting stale decrypted values reach the real device Runner.
        before = self.preserve_prior()
        entered, release = threading.Event(), threading.Event()
        decrypt = self.crypto.unprotect
        def gated(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test release timeout')
            return decrypt(*args)
        with patch.object(self.crypto, 'unprotect', side_effect=gated), \
             patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            try:
                self.app._start('apply')
                self.assertTrue(entered.wait(1))
                other = self.other()
                if delete:
                    other.delete()
                else:
                    other.save(self.data, ap_password='RotatedAP', shared_key='RotatedKey')
            finally:
                release.set()
            drain_profile(self.app)
        self.assert_no_connection()
        self.assertEqual(self.app._last_profile_error, 'PROFILE_CHANGED')
        self.assertEqual(self.app.results, before)
        self.assertFalse(self.app.busy)

    def test_rotation_during_decryption_never_reaches_loopback_controller(self):
        self.change_during_prepare(delete=False)

    def test_deletion_during_decryption_never_reaches_loopback_controller(self):
        self.change_during_prepare(delete=True)

    def test_busy_lock_prevents_connection_and_retry_after_release_queries_once(self):
        # Catches falling back to stale secrets when cooperative locking fails.
        before = self.preserve_prior()
        with exclusive_profile_lock(self.store.directory), \
             patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._start('inspect'); drain_profile(self.app)
        self.assert_no_connection()
        self.assertEqual(self.app._last_profile_error, 'PROFILE_BUSY')
        self.assertEqual(self.app.results, before)
        with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True):
            self.app._start('inspect')
            self.finish_device()
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertEqual([row.status for row in self.app.results], ['조회완료'])
        self.assertEqual(sum(command == 'show config wips summary'
                             for phase, command in self.server.commands), 1)
        self.assertFalse(any(command.startswith('config ') for phase, command in self.server.commands))

    def finish_device(self):
        deadline = time.monotonic() + 10
        while self.app.busy and time.monotonic() < deadline:
            self.root.update(); time.sleep(.005)
        self.assertFalse(self.app.busy)
        self.app.worker.join(2)
        self.assertFalse(self.app.worker.is_alive())
        self.assertFalse(self.server.errors)

    def test_refusing_close_during_preparation_starts_exactly_one_query(self):
        # Catches treating a declined close as cancellation or starting twice.
        entered, release = threading.Event(), threading.Event()
        original = self.crypto.unprotect
        def gated(*args):
            entered.set()
            if not release.wait(5): raise RuntimeError('test release timeout')
            return original(*args)
        with patch.object(self.crypto, 'unprotect', side_effect=gated):
            try:
                self.app._start('inspect'); self.assertTrue(entered.wait(1))
                with patch('wec_wips.profile_ui.messagebox.askyesno', return_value=False):
                    self.app._close()
                self.assertFalse(self.app._profile_close_requested)
                self.assertEqual(self.server.tcp_connections, 0)
            finally:
                release.set()
            self.finish_device()
        self.assertEqual(self.server.tcp_connections, 1)
        self.assertEqual([r.status for r in self.app.results], ['조회완료'])

    def test_failed_delete_after_close_request_keeps_window_and_saved_bytes(self):
        # Catches exiting silently when deletion has failed after close consent.
        entered, release = threading.Event(), threading.Event()
        before = self.store.path.read_bytes()
        def denied(*args, **kwargs):
            entered.set()
            if not release.wait(5): raise RuntimeError('test release timeout')
            raise PermissionError('PRIVATE_DELETE_CONTEXT')
        with patch('wec_wips.profile_store.Path.unlink', side_effect=denied), \
             patch('wec_wips.profile_ui.messagebox.askyesno', return_value=True), \
             patch.object(self.root, 'destroy') as destroy:
            try:
                self.app._delete_profile(); self.assertTrue(entered.wait(1))
                self.app._close()
            finally:
                release.set()
            drain_profile(self.app)
            self.assertFalse(destroy.called)
        self.assertFalse(self.app.closing)
        self.assertFalse(self.app._profile_close_requested)
        self.assertFalse(self.app.busy)
        self.assertEqual(self.app._last_profile_error, 'PROFILE_ACCESS_DENIED')
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertNotIn('PRIVATE_DELETE_CONTEXT', str(self.error.call_args))
        self.assert_no_connection()


if __name__ == '__main__':
    unittest.main()
