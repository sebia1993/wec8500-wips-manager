"""Real Tk integration with an injected non-production token protector."""
import copy
import gc
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_gui import destroy_test_root
from test_profile_store import TokenProtector, settings
from wec_wips.profile_store import ProfileStore


class ProfileUiTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('wec_wips.profile_ui'), 'Profile UI must exist')
        import tkinter as tk
        from wec_wips.profile_ui import ProfileApp
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.crypto=TokenProtector();self.store=ProfileStore(Path(self.tmp.name)/'settings',self.crypto)
        self.store.save(settings(),ap_password='SYNTHETIC_AP_PASSWORD',shared_key='SyntheticTargetKey')
        self.crypto.calls.clear()
        try:self.root=tk.Tk()
        except tk.TclError as exc:self.skipTest(f'No display: {exc}')
        self.app=ProfileApp(self.root,store=self.store)
        self.addCleanup(self.close_root)

    def close_root(self):
        destroy_test_root(self.root);self.app=self.root=None;gc.collect()

    def login(self):
        self.app.controller_user.set('operator')
        self.app.controller_password.set('SYNTHETIC_WEC_PASSWORD')

    def test_startup_restores_public_settings_but_never_decrypts_or_runs(self):
        self.assertEqual(self.crypto.calls,[])
        self.assertEqual(self.app.controller_ip.get(),'192.0.2.1')
        self.assertEqual(self.app.ap_user.get(),'root')
        self.assertEqual(self.app.controller_user.get(),'')
        self.assertEqual(self.app.controller_password.get(),'')
        self.assertEqual(self.app.ap_password.get(),'')
        self.assertEqual(self.app.shared_key.get(),'')
        self.assertTrue(self.app.use_saved_ap.get());self.assertTrue(self.app.use_saved_key.get())
        self.assertFalse(self.app.demo.get());self.assertIsNone(self.app.worker)
        self.assertEqual(self.app.results,[])

    def test_controller_credentials_still_required_before_decrypt(self):
        with self.assertRaises(ValueError):self.app._snapshot('inspect')
        self.assertEqual(self.crypto.calls,[])

    def test_query_uses_ap_password_without_decrypting_target_key(self):
        self.login();cfg=self.app._snapshot('verify_ip')
        self.assertEqual(cfg.ap_password,'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(cfg.shared_key,'')
        self.assertEqual(len(self.crypto.calls),1)
        self.assertEqual(self.app.ap_password.get(),'')

    def test_apply_uses_both_saved_secrets_but_does_not_fill_entries(self):
        self.login();cfg=self.app._snapshot('apply')
        self.assertEqual(cfg.ap_password,'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(cfg.shared_key,'SyntheticTargetKey')
        self.assertEqual(len(self.crypto.calls),2)
        self.assertEqual(self.app.ap_password.get(),'');self.assertEqual(self.app.shared_key.get(),'')

    def test_manual_secret_entries_override_saved_values(self):
        self.login();self.app.ap_password.set('ReplacementAP');self.app.shared_key.set('ReplacementKey')
        cfg=self.app._snapshot('apply')
        self.assertEqual(cfg.ap_password,'ReplacementAP');self.assertEqual(cfg.shared_key,'ReplacementKey')
        self.assertEqual(self.crypto.calls,[])

    def test_changed_controller_deselects_saved_secrets(self):
        self.login();self.app.controller_ip.set('192.0.2.2')
        self.assertFalse(self.app.use_saved_ap.get());self.assertFalse(self.app.use_saved_key.get())
        with self.assertRaises(ValueError):self.app._snapshot('inspect')
        self.assertEqual(self.crypto.calls,[])

    def test_target_server_change_invalidates_only_saved_shared_key(self):
        self.login();self.app.server_ip.set('198.51.100.21')
        self.assertTrue(self.app.use_saved_ap.get());self.assertFalse(self.app.use_saved_key.get())
        self.assertEqual(self.app._snapshot('verify_ip').ap_password,'SYNTHETIC_AP_PASSWORD')

    def test_demo_fill_does_not_decrypt_or_overwrite_saved_profile(self):
        before=self.store.path.read_bytes();self.app._fill_demo()
        cfg=self.app._snapshot('apply');self.assertTrue(cfg.demo)
        self.assertEqual(self.crypto.calls,[])
        with self.assertRaises(ValueError):self.app._save_profile_values(True,True,True)
        self.assertEqual(before,self.store.path.read_bytes())

    def test_save_with_empty_controller_credentials_and_explicit_secrets(self):
        self.app.ap_password.set('NewAP');self.app.shared_key.set('NewKey')
        self.app._save_profile_values(True,True,True)
        p=self.store.load()
        self.assertEqual(self.store.secret(p,'ap_password',p.settings),'NewAP')
        self.assertEqual(self.store.secret(p,'shared_key',p.settings),'NewKey')
        self.assertNotIn(b'controller_user',self.store.path.read_bytes())

    def test_save_retains_checked_stored_secrets_without_placeholder_strings(self):
        self.app._save_profile_values(True,True,True);p=self.store.load()
        self.assertEqual(self.store.secret(p,'ap_password',p.settings),'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(self.app.ap_password.get(),'')

    def test_save_deselects_secrets_and_targets(self):
        self.app._save_profile_values(False,False,False);p=self.store.load()
        self.assertEqual(p.secrets,{});self.assertEqual(p.settings['ap_ips'],[])
        self.assertEqual(p.settings['ap_hostnames'],{})
        self.assertFalse(self.app.use_saved_ap.get());self.assertFalse(self.app.use_saved_key.get())

    def test_secret_decryption_failure_does_not_connect_or_destroy_profile(self):
        self.login();before=self.store.path.read_bytes()
        with patch.object(self.crypto,'unprotect',side_effect=RuntimeError('DO_NOT_SHOW_SECRET')):
            with patch('wec_wips.gui.messagebox.showerror') as error,patch('wec_wips.gui.threading.Thread.start') as start:
                self.app._start('inspect')
        start.assert_not_called();self.assertNotIn('DO_NOT_SHOW_SECRET',str(error.call_args))
        self.assertEqual(before,self.store.path.read_bytes());self.assertFalse(self.app.busy)

    def test_corrupt_profile_does_not_autostart_or_replace_file(self):
        self.store.path.write_bytes(b'{corrupt')
        self.app._load_profile(silent=True)
        self.assertIsNone(self.app._profile);self.assertFalse(self.app.use_saved_ap.get())
        self.assertEqual(self.store.path.read_bytes(),b'{corrupt');self.assertIsNone(self.app.worker)

    def test_busy_blocks_save_load_delete(self):
        before=self.store.path.read_bytes();self.app._set_busy(True)
        with self.assertRaises(ValueError):self.app._save_profile_values(False,False,False)
        self.app._load_profile();self.app._delete_profile()
        self.assertEqual(before,self.store.path.read_bytes())
        self.assertEqual(str(self.app.profile_save_button['state']),'disabled')
        self.app._set_busy(False)

    def test_delete_confirmation_removes_only_profile_not_reports_or_results(self):
        keep=self.store.directory/'report.txt';keep.write_bytes(b'report')
        self.app.results=['synthetic preserved result']
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=True):self.app._delete_profile()
        self.assertFalse(self.store.path.exists());self.assertEqual(keep.read_bytes(),b'report')
        self.assertEqual(self.app.results,['synthetic preserved result'])
        self.assertFalse(self.app.use_saved_ap.get())

    def test_delete_cancel_keeps_profile(self):
        before=self.store.path.read_bytes()
        with patch('wec_wips.profile_ui.messagebox.askyesno',return_value=False):self.app._delete_profile()
        self.assertEqual(before,self.store.path.read_bytes())

    def test_reload_clears_controller_credentials(self):
        self.login();self.app._load_profile()
        self.assertEqual(self.app.controller_user.get(),'');self.assertEqual(self.app.controller_password.get(),'')

    def test_stored_ap_does_not_change_ip_only_validation_policy(self):
        self.login()
        self.app.syntax.set('NAT 생략 · 해당 장비 문법 확인 필요')
        self.app.nat_mode.set('2 · NAT 사용')
        try:
            cfg=self.app._snapshot('verify_ip')
        except ValueError as exc:
            self.fail('IP-only mode must ignore unused syntax/NAT settings: '+str(exc))
        self.assertEqual(cfg.ap_password,'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(cfg.nat_mode,'2')

    def test_stored_ap_does_not_require_target_server_for_inspect(self):
        self.login();self.app.server_ip.set('unfinished target')
        try:
            cfg=self.app._snapshot('inspect')
        except ValueError as exc:
            self.fail('Inspection must not validate an unused target server: '+str(exc))
        self.assertEqual(cfg.ap_password,'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(cfg.server_ip,'unfinished target')

    def test_save_failure_keeps_in_memory_profile_and_form_secrets(self):
        original=self.app._profile
        self.app.ap_password.set('UnsavedReplacement')
        with patch.object(self.crypto,'protect',side_effect=RuntimeError('do not expose')):
            with self.assertRaises(ValueError):self.app._save_profile_values(True,False,True)
        self.assertIs(self.app._profile,original)
        self.assertEqual(self.app.ap_password.get(),'UnsavedReplacement')

    def test_unsupported_platform_keeps_manual_demo_available(self):
        from wec_wips.profile_ui import ProfileApp
        import tkinter as tk
        root=tk.Tk()
        try:
            app=ProfileApp(root,store=None)
            app._fill_demo();self.assertTrue(app._snapshot('inspect').demo)
            self.assertEqual(str(app.profile_save_button['state']),'disabled')
        finally:destroy_test_root(root)

if __name__=='__main__':unittest.main()
