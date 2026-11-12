"""Run on Windows: py -3 tests/windows_profile_check.py

Synthetic secrets and TemporaryDirectory only; never touches the live profile or network.
This script is deliberately separate from Linux unittest discovery.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from wec_wips.dpapi import DpapiProtector
from wec_wips.profile_store import ProfileStore, ProfileError


class WindowsProfileChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=ProfileStore(Path(self.tmp.name))
        self.data=dict(controller_ip='192.0.2.1',ap_user='root',server_ip='198.51.100.20')

    def test_native_roundtrip_new_store_instance(self):
        self.store.save(self.data,ap_password='SyntheticOnly!123',shared_key='SyntheticKey123')
        other=ProfileStore(Path(self.tmp.name));p=other.load()
        self.assertEqual(other.secret(p,'ap_password',p.settings),'SyntheticOnly!123')
        self.assertEqual(other.secret(p,'shared_key',p.settings),'SyntheticKey123')
        raw=other.path.read_text('utf-8')
        self.assertNotIn('SyntheticOnly!123',raw);self.assertNotIn('controller_password',raw)

    def test_native_entropy_binding(self):
        p=self.store.save(self.data,ap_password='SyntheticOnly!123')
        doc=json.loads(self.store.path.read_text('utf-8'))
        doc['settings']['controller_ip']='192.0.2.2'
        self.store.path.write_text(json.dumps(doc),encoding='utf-8')
        changed=self.store.load()
        with self.assertRaises(ProfileError):self.store.secret(changed,'ap_password',changed.settings)

    def test_native_corruption_fails_closed(self):
        self.store.save(self.data,ap_password='SyntheticOnly!123')
        import base64
        doc=json.loads(self.store.path.read_text('utf-8'))
        value=bytearray(base64.b64decode(doc['secrets']['ap_password']))
        value[len(value)//2]^=0x7F
        doc['secrets']['ap_password']=base64.b64encode(value).decode()
        self.store.path.write_text(json.dumps(doc),encoding='utf-8')
        p=self.store.load()
        with self.assertRaises(ProfileError):self.store.secret(p,'ap_password',p.settings)

    def test_native_update_and_delete(self):
        self.store.save(self.data,ap_password='FirstSynthetic')
        self.store.save(self.data,ap_password='SecondSynthetic')
        p=self.store.load();self.assertEqual(self.store.secret(p,'ap_password',p.settings),'SecondSynthetic')
        self.store.delete();self.assertIsNone(self.store.load())

    def test_native_stale_window_cannot_revert_or_delete_new_secrets(self):
        self.store.save(self.data, ap_password='OriginalSynthetic')
        old = ProfileStore(Path(self.tmp.name)); old.load()
        self.store.save(self.data, ap_password='RotatedSynthetic')
        with self.assertRaises(ProfileError) as caught:
            old.save(self.data, ap_password='OriginalSynthetic')
        self.assertEqual(caught.exception.code, 'PROFILE_CHANGED')
        with self.assertRaises(ProfileError):
            old.delete()
        current = self.store.load()
        self.assertEqual(self.store.secret(current, 'ap_password', current.settings), 'RotatedSynthetic')

    def test_native_lock_excludes_a_second_process(self):
        import subprocess
        from wec_wips.profile_lock import exclusive_profile_lock
        self.store.save(self.data)
        script = """
from pathlib import Path
import sys
from wec_wips.profile_store import ProfileStore, ProfileError
s=ProfileStore(Path(sys.argv[1]));p=s.load()
try:
    s.save(p.settings)
except ProfileError as e:
    print(e.code)
else:
    print('UNEXPECTED_WRITE')
"""
        with exclusive_profile_lock(Path(self.tmp.name)):
            result = subprocess.run([sys.executable, '-c', script, self.tmp.name],
                                    cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PROFILE_BUSY')
        self.store.save(self.data)  # OS lock released, not a permanent PID lock.

if __name__=='__main__':
    if sys.platform != 'win32':
        print('NOT RUN: native Windows DPAPI requires Windows. No fallback is used.')
        raise SystemExit(2)
    unittest.main(verbosity=2)
