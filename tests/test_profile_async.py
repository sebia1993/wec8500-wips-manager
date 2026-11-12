"""Exercise user callbacks with slow storage/protection, no equipment access."""
import copy
import gc
from pathlib import Path
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from test_gui import destroy_test_root
from test_profile_store import TokenProtector, settings
from profile_test_support import drain_profile, resolved_snapshot
from wec_wips.profile_store import ProfileStore
from wec_wips.profile_ui import ProfileApp
from wec_wips.core import Result


class ProfileAsyncFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.crypto=TokenProtector()
        self.store=ProfileStore(Path(self.tmp.name)/'settings',self.crypto)
        self.store.save(settings(),ap_password='SyntheticAP',shared_key='SyntheticKey')
        self.root=tk.Tk();self.app=ProfileApp(self.root,store=self.store)
        drain_profile(self.app)
        self.errors=patch('wec_wips.profile_ui.messagebox.showerror');self.error=self.errors.start()
        self.app.controller_user.set('operator');self.app.controller_password.set('SyntheticWecPassword')

    def tearDown(self):
        drain_profile(self.app)
        self.errors.stop();destroy_test_root(self.root);self.app=self.root=None;gc.collect();self.tmp.cleanup()

    def check_responsive(self, obj, name, action, delay=.30):
        original=getattr(obj,name);threads=[];ticks=[]
        def slow(*args,**kwargs):
            threads.append(threading.get_ident())
            time.sleep(delay)
            return original(*args,**kwargs)
        self.root.after(20,lambda:ticks.append(getattr(self.app,'_profile_busy',False)))
        start=time.monotonic()
        with patch.object(obj,name,side_effect=slow):
            action()
            elapsed=time.monotonic()-start
            # Ensure work is still pending when normal Tk callbacks can run.
            deadline=time.monotonic()+2
            while not ticks and time.monotonic()<deadline:
                self.root.update();time.sleep(.005)
            drain_profile(self.app)
        self.assertLess(elapsed,.20,'User callback blocked on profile I/O/crypto')
        self.assertEqual(ticks,[True],'Heartbeat must run while profile work is pending')
        self.assertTrue(threads)
        self.assertTrue(all(t != threading.get_ident() for t in threads),'Worker called API on Tk thread')


class ProfileAsyncTests(ProfileAsyncFixture):
    def test_slow_save_returns_to_event_loop(self):
        self.check_responsive(self.crypto,'protect',lambda:self.app._save_profile_values(True,True,True))
        self.assertFalse(self.app.busy)

    def test_slow_prepare_does_not_freeze_or_start_twice(self):
        with patch.object(self.app,'_begin') as begin:
            self.check_responsive(self.crypto,'unprotect',lambda:self.app._start('inspect'))
        self.assertEqual(begin.call_count,1)
        self.assertEqual(begin.call_args.args[0].ap_password,'SyntheticAP')

    def test_slow_load_returns_to_event_loop(self):
        self.check_responsive(self.store,'load',lambda:self.app._load_profile())

    def test_slow_delete_returns_to_event_loop(self):
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):
            self.check_responsive(self.store,'delete',lambda:self.app._delete_profile())
        self.assertFalse(self.store.path.exists())

    def test_resume_explains_old_credentials_and_cancel_preserves_evidence(self):
        self.app.saved_config=resolved_snapshot(self.app,'inspect')
        self.app.saved_mode='inspect'
        self.app.results=[Result('2026-11-12','192.0.2.11','확인불가',mode='inspect',config_sent=True,expected_nat='2')]
        evidence=copy.deepcopy(self.app.results)
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=False) as ask,patch.object(self.app,'_begin') as begin:
            self.app._resume()
        self.assertTrue(ask.called,'Resume requires explicit old-credential notice')
        self.assertIn('이전',str(ask.call_args));self.assertIn('비밀번호',str(ask.call_args))
        begin.assert_not_called();self.assertEqual(self.app.results,evidence)



class ProfileAsyncBoundaryTests(ProfileAsyncFixture):

    def other(self):
        store=ProfileStore(self.store.directory,self.crypto);store.load();return store

    def test_old_window_save_cannot_revert_rotated_password(self):
        other=self.other();other.save(settings(),ap_password='RotatedAP',shared_key='RotatedKey')
        before=self.store.path.read_bytes()
        self.app.timeout.set('30');self.app._save_profile_values(True,True,True)
        drain_profile(self.app)
        self.assertEqual(self.app._last_profile_error,'PROFILE_CHANGED')
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertEqual(self.store.secret(other.load(),'ap_password',settings()),'RotatedAP')

    def test_old_window_delete_cannot_remove_rotated_profile(self):
        self.other().save(settings(),ap_password='RotatedAP')
        before=self.store.path.read_bytes()
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):
            self.app._delete_profile()
            drain_profile(self.app)
        self.assertEqual(self.app._last_profile_error,'PROFILE_CHANGED')
        self.assertEqual(self.store.path.read_bytes(),before)

    def test_new_job_after_external_delete_never_connects(self):
        self.other().delete()
        with patch.object(self.app,'_begin') as begin:
            self.app._start('inspect');drain_profile(self.app)
        begin.assert_not_called()
        self.assertEqual(self.app._last_profile_error,'PROFILE_CHANGED')
        self.assertFalse(self.store.path.exists())

    def test_manual_password_does_not_bypass_changed_profile_targets(self):
        self.other().save(settings(),ap_password='RotatedAP')
        self.app.ap_password.set('ManualAP')
        with patch.object(self.app,'_begin') as begin:
            self.app._start('inspect');drain_profile(self.app)
        begin.assert_not_called()
        self.assertEqual(self.app._last_profile_error,'PROFILE_CHANGED')

    def test_reload_after_conflict_allows_new_saved_password(self):
        self.other().save(settings(),ap_password='RotatedAP')
        self.app._load_profile();drain_profile(self.app)
        self.app.controller_user.set('operator');self.app.controller_password.set('SyntheticWecPassword')
        with patch.object(self.app,'_begin') as begin:
            self.app._start('inspect');drain_profile(self.app)
        self.assertEqual(begin.call_count,1)
        self.assertEqual(begin.call_args.args[0].ap_password,'RotatedAP')

    def test_profile_thread_start_failure_restores_buttons_and_prior_results(self):
        before=self.store.path.read_bytes()
        self.app.results=[Result('2026-11-12','192.0.2.11','확인불가',config_sent=True,expected_nat='2')]
        expected=copy.deepcopy(self.app.results)
        with patch('wec_wips.profile_ui.threading.Thread.start',side_effect=RuntimeError('SENSITIVE_EXCEPTION')):
            self.app._save_profile_values(True,True,True)
            drain_profile(self.app)
        self.assertFalse(self.app.busy)
        self.assertEqual(str(self.app.profile_save_button['state']),'normal')
        self.assertEqual(self.app._last_profile_error,'PROFILE_WORKER_FAILED')
        self.assertEqual(self.app.results,expected)
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertNotIn('SENSITIVE_EXCEPTION',str(self.error.call_args))

    def test_slow_job_blocks_duplicate_operations_and_form_edits(self):
        entered=threading.Event();release=threading.Event();real=self.crypto.protect
        def slow(*args):
            entered.set();release.wait(3);return real(*args)
        with patch.object(self.crypto,'protect',side_effect=slow):
            self.app._save_profile_values(True,False,True)
            self.assertTrue(entered.wait(1))
            self.assertTrue(self.app.busy)
            self.assertEqual(str(self.app.profile_load_button['state']),'disabled')
            self.assertEqual(str(self.app.controller_entry['state']),'disabled')
            token=self.app._profile_token
            self.app._start('inspect');self.app._load_profile();self.app._delete_profile()
            self.assertEqual(self.app._profile_token,token)
            with self.assertRaises(ValueError):self.app._save_profile_values(True,False,True)
            release.set();drain_profile(self.app)
        self.assertFalse(self.app.busy)

    def test_close_during_preparation_discards_ready_device_start(self):
        entered=threading.Event();release=threading.Event();real=self.crypto.unprotect
        def slow(*args):entered.set();release.wait(3);return real(*args)
        with patch.object(self.crypto,'unprotect',side_effect=slow),patch.object(self.app,'_begin') as begin, \
             patch.object(self.root,'destroy') as destroy,patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):
            self.app._start('inspect');self.assertTrue(entered.wait(1))
            self.app._close();self.root.update()
            self.assertFalse(destroy.called)
            release.set();drain_profile(self.app)
            begin.assert_not_called();self.assertTrue(destroy.called)
        self.app.closing=False;self.app._profile_close_requested=False

    def test_close_during_save_waits_for_atomic_commit(self):
        entered=threading.Event();release=threading.Event();real=self.crypto.protect
        def slow(*args):entered.set();release.wait(3);return real(*args)
        self.app.ap_password.set('NewAPAfterClose')
        with patch.object(self.crypto,'protect',side_effect=slow),patch.object(self.root,'destroy') as destroy, \
             patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):
            self.app._save_profile_values(True,False,True);self.assertTrue(entered.wait(1))
            self.app._close();self.root.update();self.assertFalse(destroy.called)
            release.set();drain_profile(self.app);self.assertTrue(destroy.called)
        self.app.closing=False;self.app._profile_close_requested=False
        p=self.store.load();self.assertEqual(self.store.secret(p,'ap_password',p.settings),'NewAPAfterClose')

    def test_save_failure_keeps_manual_value_and_file(self):
        before=self.store.path.read_bytes();self.app.ap_password.set('ManualNotCommitted')
        with patch.object(self.crypto,'protect',side_effect=RuntimeError('SENSITIVE_FAILURE')):
            self.app._save_profile_values(True,False,True);drain_profile(self.app)
        self.assertEqual(self.app.ap_password.get(),'ManualNotCommitted')
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertEqual(self.app._last_profile_error,'PROFILE_PROTECT_FAILED')
        self.assertNotIn('SENSITIVE_FAILURE',str(self.error.call_args))

    def test_resume_notice_does_not_replace_original_credentials_or_write_evidence(self):
        self.app.saved_config=resolved_snapshot(self.app,'apply');self.app.saved_mode='apply'
        self.app.results=[Result('2026-11-12','192.0.2.11','확인불가',mode='apply',config_sent=True,expected_nat='2')]
        prior=copy.deepcopy(self.app.results)
        self.app.ap_password.set('NewTypedPassword')
        self.app._save_profile_values(True,True,True);drain_profile(self.app)
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True) as ask,patch.object(self.app,'_begin') as begin:
            self.app._resume()
        self.assertEqual(begin.call_count,1)
        self.assertEqual(begin.call_args.args[0].ap_password,'SyntheticAP')
        self.assertEqual(begin.call_args.args[2],prior)
        self.assertIn('비밀번호',str(ask.call_args_list[0]))

    def test_manual_configuration_without_profile_keeps_working(self):
        self.other().delete();self.app._load_profile();drain_profile(self.app)
        self.app.ap_password.set('ManualAP')
        with patch.object(self.app,'_begin') as begin:
            self.app._start('inspect')
        self.assertEqual(begin.call_count,1)
        self.assertEqual(begin.call_args.args[0].ap_password,'ManualAP')
        self.assertFalse(self.app._profile_busy)

    def test_close_request_does_not_hide_failed_save_or_discard_manual_password(self):
        entered=threading.Event();release=threading.Event()
        before=self.store.path.read_bytes()
        def fail(*args):
            entered.set();release.wait(3)
            raise RuntimeError('SENSITIVE_FAILURE')
        self.app.ap_password.set('UnsavedPassword')
        with patch.object(self.crypto,'protect',side_effect=fail),patch.object(self.root,'destroy') as destroy, \
             patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):
            self.app._save_profile_values(True,False,True);self.assertTrue(entered.wait(1))
            self.app._close();release.set();drain_profile(self.app)
            self.assertFalse(destroy.called, 'A failed save must remain visible rather than silently exiting')
            self.assertFalse(self.app.closing)
            self.assertFalse(self.app._profile_close_requested)
            self.assertTrue(self.error.called)
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertEqual(self.app.ap_password.get(),'UnsavedPassword')

    def test_three_second_save_keeps_tk_responsive(self):
        self.check_responsive(self.crypto,'protect',
                              lambda:self.app._save_profile_values(True,False,True),delay=3.0)

    def test_prepared_config_uses_captured_data_not_later_widget_values(self):
        entered=threading.Event();release=threading.Event();real=self.crypto.unprotect
        def slow(*args):entered.set();release.wait(3);return real(*args)
        with patch.object(self.crypto,'unprotect',side_effect=slow),patch.object(self.app,'_begin') as begin:
            self.app._start('inspect');self.assertTrue(entered.wait(1))
            self.assertEqual(str(self.app.controller_entry['state']),'disabled')
            # Programmatic mutation is not a permitted UI edit. It still must not
            # alter a snapshot already handed to a worker.
            self.app.controller_ip.set('192.0.2.200')
            self.app.controller_password.set('ChangedDuringPrepare')
            release.set();drain_profile(self.app)
        self.assertEqual(begin.call_args.args[0].controller_ip,'192.0.2.1')
        self.assertEqual(begin.call_args.args[0].controller_password,'SyntheticWecPassword')

if __name__=='__main__': unittest.main()
