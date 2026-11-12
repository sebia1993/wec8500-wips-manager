"""Persistence contract tests. TokenProtector is a test double, never a cipher."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def settings():
    return dict(controller_ip='192.0.2.1', controller_port=23,
                ap_user='root', ap_port=50022, server_ip='198.51.100.20',
                syntax='with_nat', nat_mode='keep', timeout=20,
                auto_recover=True, stop_on_error=True,
                auto_accept_ap_host_key=True, lookup_hostnames=True,
                ap_ips=['192.0.2.11'], ap_hostnames={'192.0.2.11':'LAB-AP11'})


class TokenProtector:
    def __init__(self):
        self.values = {}; self.calls = []
    def protect(self, data, entropy):
        token = os.urandom(32)
        self.values[token] = (data, entropy)
        self.calls.append(('protect', entropy))
        return token
    def unprotect(self, token, entropy):
        self.calls.append(('unprotect', entropy))
        data, expected = self.values[token]
        if entropy != expected:
            raise ValueError('synthetic failure must not leak')
        return data


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('wec_wips.profile_store'),
                             'ProfileStore feature must exist')
        from wec_wips.profile_store import ProfileStore, ProfileError
        self.Error = ProfileError
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'settings'
        self.crypto = TokenProtector()
        self.store = ProfileStore(self.root, self.crypto)

    def test_absent_profile_does_not_create_files(self):
        self.assertIsNone(self.store.load()); self.assertFalse(self.root.exists())

    def test_save_load_is_lazy_and_excludes_controller_credentials(self):
        saved = self.store.save(settings(), ap_password='SYNTHETIC_AP_PASSWORD', shared_key='SyntheticTargetKey')
        raw = self.store.path.read_bytes()
        for value in (b'SYNTHETIC_AP_PASSWORD', b'SyntheticTargetKey', b'controller_user', b'controller_password'):
            self.assertNotIn(value, raw)
        self.crypto.calls.clear()
        loaded = self.store.load()
        self.assertEqual(loaded.settings, settings()); self.assertEqual(self.crypto.calls, [])
        self.assertEqual(self.store.secret(loaded, 'ap_password', settings()), 'SYNTHETIC_AP_PASSWORD')
        self.assertEqual(self.store.secret(loaded, 'shared_key', settings()), 'SyntheticTargetKey')
        self.assertNotIn('SYNTHETIC_AP_PASSWORD', repr(loaded))
        self.assertEqual(saved.settings, loaded.settings)

    def test_secrets_require_explicit_selection(self):
        self.store.save(settings())
        self.assertEqual(self.store.load().secrets, {}); self.assertEqual(self.crypto.calls, [])
        self.store.save(settings(), ap_password='SyntheticAP')
        self.assertEqual(set(self.store.load().secrets), {'ap_password'})
        self.store.save(settings())
        self.assertEqual(self.store.load().secrets, {})

    def test_rejects_controller_credentials_or_unlisted_fields(self):
        for key in ('controller_password','controller_user','demo','raw','auto_start'):
            with self.subTest(key=key):
                bad=settings(); bad[key]='DO_NOT_STORE'
                with self.assertRaises(self.Error): self.store.save(bad)
                self.assertFalse(self.store.path.exists())

    def test_encryption_failure_preserves_previous_file_and_no_plaintext_temp(self):
        self.store.save(settings()); original=self.store.path.read_bytes()
        with patch.object(self.crypto,'protect',side_effect=RuntimeError('SYNTHETIC_AP_PASSWORD')):
            with self.assertRaises(self.Error) as err: self.store.save(settings(),ap_password='SYNTHETIC_AP_PASSWORD')
        self.assertNotIn('SYNTHETIC_AP_PASSWORD',str(err.exception))
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertEqual(set(self.root.iterdir()), {self.store.path, self.root / '.profile.lock'})
        self.assertEqual((self.root / '.profile.lock').read_bytes(), b'')

    def test_replace_failure_preserves_previous_file_and_cleans_temp(self):
        self.store.save(settings()); original=self.store.path.read_bytes()
        with patch('wec_wips.profile_store.os.replace',side_effect=PermissionError('secret path')):
            with self.assertRaises(self.Error): self.store.save(settings(),ap_password='SyntheticAP')
        self.assertEqual(self.store.path.read_bytes(),original)
        self.assertEqual(set(self.root.iterdir()), {self.store.path, self.root / '.profile.lock'})
        self.assertEqual((self.root / '.profile.lock').read_bytes(), b'')

    def test_each_endpoint_change_blocks_stored_ap_secret_before_decrypt(self):
        p=self.store.save(settings(),ap_password='SyntheticAP')
        for key,value in [('controller_ip','192.0.2.2'),('controller_port',2323),('ap_user','operator'),('ap_port',22)]:
            with self.subTest(key=key):
                changed=settings(); changed[key]=value; self.crypto.calls.clear()
                with self.assertRaises(self.Error): self.store.secret(p,'ap_password',changed)
                self.assertEqual(self.crypto.calls,[])

    def test_shared_key_binding_changes_with_target_but_ap_password_does_not(self):
        p=self.store.save(settings(),ap_password='SyntheticAP',shared_key='SyntheticKey')
        changed=settings();changed['server_ip']='198.51.100.21'
        self.assertEqual(self.store.secret(p,'ap_password',changed),'SyntheticAP')
        with self.assertRaises(self.Error): self.store.secret(p,'shared_key',changed)

    def test_nonidentity_changes_do_not_invalidate_secret(self):
        p=self.store.save(settings(),ap_password='SyntheticAP')
        s=settings();s['timeout']=30;s['ap_ips']=[];s['ap_hostnames']={}
        self.assertEqual(self.store.secret(p,'ap_password',s),'SyntheticAP')

    def test_disk_endpoint_tampering_fails_at_decryption(self):
        self.store.save(settings(),ap_password='SyntheticAP')
        doc=json.loads(self.store.path.read_text());doc['settings']['controller_ip']='192.0.2.2'
        self.store.path.write_text(json.dumps(doc))
        p=self.store.load()
        with self.assertRaises(self.Error):self.store.secret(p,'ap_password',p.settings)

    def test_different_user_protector_cannot_read_secrets(self):
        from wec_wips.profile_store import ProfileStore
        self.store.save(settings(),ap_password='SyntheticAP')
        other=ProfileStore(self.root,TokenProtector());p=other.load()
        with self.assertRaises(self.Error):other.secret(p,'ap_password',settings())
        self.assertTrue(self.store.path.exists())

    def test_malformed_duplicate_unknown_or_oversize_file_is_rejected_without_rewrite(self):
        self.root.mkdir()
        for payload in (b'{', b'{"schema":1,"schema":1}',b'[]',b'X'*(2*1024*1024+1)):
            with self.subTest(size=len(payload)):
                self.store.path.write_bytes(payload)
                with self.assertRaises(self.Error):self.store.load()
                self.assertEqual(self.store.path.read_bytes(),payload)

    def test_corrupt_ciphertext_does_not_replace_file(self):
        self.store.save(settings(),ap_password='SyntheticAP')
        doc=json.loads(self.store.path.read_text());doc['secrets']['ap_password']='not base64!!!'
        original=json.dumps(doc).encode();self.store.path.write_bytes(original)
        with self.assertRaises(self.Error):self.store.load()
        self.assertEqual(self.store.path.read_bytes(),original)

    def test_plaintext_secret_envelope_is_checked_after_unprotect(self):
        p=self.store.save(settings(),ap_password='SyntheticAP')
        for payload in (b'{}',b'[]',b'not-json',json.dumps({'schema':1,'kind':'shared_key','value':'SyntheticAP','binding':{}}).encode()):
            with patch.object(self.crypto,'unprotect',return_value=payload), self.assertRaises(self.Error):
                self.store.secret(p,'ap_password',settings())

    def test_bad_public_settings_do_not_save(self):
        for key,value in [('controller_port',True),('timeout',float('nan')),('auto_recover','true'),('ap_user','root\nexit'),('ap_ips',['not-ip']),('controller_ip','0.0.0.0')]:
            with self.subTest(key=key):
                bad=settings();bad[key]=value
                with self.assertRaises(self.Error):self.store.save(bad)
        self.assertFalse(self.store.path.exists())

    def test_bad_password_or_key_never_written(self):
        for kind,value in [('ap_password',''),('ap_password','bad\nvalue'),('shared_key','bad key'),('shared_key','')]:
            with self.subTest(kind=kind),self.assertRaises(self.Error):self.store.save(settings(),**{kind:value})
        self.assertFalse(self.store.path.exists())

    def test_delete_removes_only_profile_and_is_idempotent(self):
        self.store.save(settings(),ap_password='SyntheticAP')
        other=self.root/'unrelated.txt';other.write_bytes(b'keep')
        self.store.delete();self.store.delete()
        self.assertIsNone(self.store.load());self.assertEqual(other.read_bytes(),b'keep')

    def test_delete_failure_keeps_saved_profile(self):
        self.store.save(settings());before=self.store.path.read_bytes()
        with patch('wec_wips.profile_store.Path.unlink',side_effect=PermissionError('internal')):
            with self.assertRaises(self.Error):self.store.delete()
        self.assertEqual(before,self.store.path.read_bytes())

    def test_missing_persisted_setting_is_corruption_not_new_defaults(self):
        self.store.save(settings())
        doc=json.loads(self.store.path.read_text());del doc['settings']['ap_user']
        raw=json.dumps(doc).encode();self.store.path.write_bytes(raw)
        with self.assertRaises(self.Error):self.store.load()
        self.assertEqual(self.store.path.read_bytes(),raw)

    def test_optional_ap_list_can_be_empty(self):
        s=settings();s['ap_ips']=[];s['ap_hostnames']={}
        self.assertEqual(self.store.save(s).settings,s)

    def test_input_objects_are_not_mutated(self):
        s=settings();before=copy.deepcopy(s);p=self.store.save(s,ap_password='SyntheticAP')
        s['ap_ips'].append('192.0.2.12')
        self.assertEqual(p.settings,before)


if __name__=='__main__':unittest.main()
