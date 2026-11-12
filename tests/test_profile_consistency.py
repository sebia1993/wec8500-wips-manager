"""Cross-window consistency regression. Synthetic secrets, temporary files only."""
from pathlib import Path
import tempfile
import unittest
from test_profile_store import TokenProtector, settings
from wec_wips.profile_store import ProfileError, ProfileStore


class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.crypto = TokenProtector()
        self.a = ProfileStore(Path(self.tmp.name), self.crypto)
        self.old = self.a.save(settings(), ap_password='OldSynthetic')
        self.b = ProfileStore(Path(self.tmp.name), self.crypto)
        self.stale = self.b.load()

    def test_stale_writer_cannot_revert_new_password(self):
        self.a.save(settings(), ap_password='NewSynthetic')
        newest = self.a.path.read_bytes()
        with self.assertRaises(ProfileError):
            self.b.save(settings(), ap_password='OldSynthetic')
        self.assertEqual(self.a.path.read_bytes(), newest)

    def test_stale_delete_cannot_remove_new_profile(self):
        self.a.save(settings(), ap_password='NewSynthetic')
        newest = self.a.path.read_bytes()
        with self.assertRaises(ProfileError): self.b.delete()
        self.assertEqual(self.a.path.read_bytes(), newest)

    def test_deleted_profile_cannot_be_silently_recreated(self):
        self.a.delete()
        with self.assertRaises(ProfileError): self.b.save(settings(), ap_password='OldSynthetic')
        self.assertFalse(self.a.path.exists())

    def test_deleted_profile_cannot_supply_cached_secret(self):
        self.a.delete()
        with self.assertRaises(ProfileError): self.b.secret(self.stale, 'ap_password', settings())

    def test_changed_profile_cannot_supply_cached_secret(self):
        self.a.save(settings(), ap_password='NewSynthetic')
        with self.assertRaises(ProfileError): self.b.secret(self.stale, 'ap_password', settings())

    def test_two_new_windows_cannot_overwrite_first_creation(self):
        other_dir=Path(self.tmp.name)/'fresh'
        a=ProfileStore(other_dir,self.crypto);b=ProfileStore(other_dir,self.crypto)
        self.assertIsNone(a.load());self.assertIsNone(b.load())
        a.save(settings(),ap_password='FirstSynthetic')
        with self.assertRaises(ProfileError): b.save(settings(),ap_password='SecondSynthetic')


class LockAndRevisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.crypto=TokenProtector();self.store=ProfileStore(Path(self.tmp.name),self.crypto)
        self.profile=self.store.save(settings(),ap_password='SyntheticValue')

    def test_error_has_fixed_conflict_code_without_secret(self):
        other=ProfileStore(self.store.directory,self.crypto);other.load()
        self.store.save(settings(),ap_password='SENSITIVE_NEW_SYNTHETIC')
        with self.assertRaises(ProfileError) as error: other.save(settings(),ap_password='SENSITIVE_OLD_SYNTHETIC')
        self.assertEqual(error.exception.code,'PROFILE_CHANGED')
        self.assertNotIn('SENSITIVE',str(error.exception))

    def test_revision_is_memory_only_and_old_schema_still_loads(self):
        import hashlib,json
        raw=self.store.path.read_bytes();p=self.store.load()
        self.assertEqual(p.revision,hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.store.observed_revision,p.revision)
        self.assertEqual(set(json.loads(raw)),{'schema','settings','secrets'})
        self.assertEqual(json.loads(raw)['schema'],1)

    def test_rotation_during_decryption_does_not_return_old_password(self):
        from unittest.mock import patch
        other=ProfileStore(self.store.directory,self.crypto);other.load()
        real=self.crypto.unprotect
        def rotate(token,entropy):
            other.save(settings(),ap_password='RotatedSynthetic')
            return real(token,entropy)
        with patch.object(self.crypto,'unprotect',side_effect=rotate):
            with self.assertRaises(ProfileError) as error:
                self.store.secret(self.profile,'ap_password',settings())
        self.assertEqual(error.exception.code,'PROFILE_CHANGED')

    def test_commit_rechecks_revision_after_encryption(self):
        from unittest.mock import patch
        other=ProfileStore(self.store.directory,self.crypto);other.load()
        real=self.crypto.protect;count=0
        def rotate(data,entropy):
            nonlocal count
            count+=1
            if count==1: other.save(settings())
            return real(data,entropy)
        with patch.object(self.crypto,'protect',side_effect=rotate):
            with self.assertRaises(ProfileError) as error:
                self.store.save(settings(),ap_password='DelayedSynthetic')
        self.assertEqual(error.exception.code,'PROFILE_CHANGED')
        self.assertEqual(other.load().secrets,{})

    def test_lock_conflict_never_updates_file(self):
        from wec_wips.profile_lock import exclusive_profile_lock
        before=self.store.path.read_bytes()
        with exclusive_profile_lock(self.store.directory):
            with self.assertRaises(ProfileError) as error:self.store.save(settings())
            self.assertEqual(error.exception.code,'PROFILE_BUSY')
        self.assertEqual(self.store.path.read_bytes(),before)
        self.store.save(settings())  # release must restore availability

    def test_corrupt_loaded_file_can_be_explicitly_deleted_but_not_newer_replacement(self):
        self.store.path.write_bytes(b'{corrupt')
        with self.assertRaises(ProfileError):self.store.load()
        self.store.delete()
        self.assertFalse(self.store.path.exists())

    def test_lock_file_retained_and_empty(self):
        from wec_wips.profile_lock import LOCK_NAME
        self.store.delete()
        self.assertEqual((self.store.directory/LOCK_NAME).read_bytes(),b'')
        self.assertEqual(list(self.store.directory.iterdir()),[self.store.directory/LOCK_NAME])

    def test_failed_atomic_replace_preserves_observed_revision(self):
        from unittest.mock import patch
        before=self.store.observed_revision
        with patch('wec_wips.profile_store.os.replace',side_effect=OSError('PRIVATE')):
            with self.assertRaises(ProfileError):self.store.save(settings())
        self.assertEqual(self.store.observed_revision,before)
        self.store.assert_current(before)

    def test_real_process_contention_is_serialized(self):
        import subprocess,sys,json,os
        # Both children load the same snapshot, then are released simultaneously.
        ready=self.store.directory/'ready';ready.mkdir()
        code="""
import sys,time,json
from pathlib import Path
from wec_wips.profile_store import ProfileStore,ProfileError
p=Path(sys.argv[1]);i=sys.argv[2];s=ProfileStore(p);old=s.load()
(p/'ready'/i).touch()
while not (p/'go').exists():time.sleep(.005)
try:
 values=dict(old.settings);values['timeout']=int(i)+30
 s.save(values)
 result='saved'
except ProfileError as e:result=e.code
print(result,flush=True)
"""
        processes=[subprocess.Popen([sys.executable,'-c',code,str(self.store.directory),str(i)],
                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in (1,2)]
        import time
        try:
            deadline=time.monotonic()+5
            while len(list(ready.iterdir()))<2 and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(len(list(ready.iterdir())),2)
            (self.store.directory/'go').touch()
            values=[]
            for process in processes:
                out,err=process.communicate(timeout=5)
                self.assertEqual(process.returncode,0,err)
                values.append(out.strip())
            self.assertEqual(values.count('saved'),1,values)
            self.assertTrue(any(v in ('PROFILE_BUSY','PROFILE_CHANGED') for v in values),values)
            self.assertIn(self.store.load().settings['timeout'],(31,32))
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.communicate()

    def test_windows_lock_contract_is_nonblocking_one_byte(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from wec_wips.profile_lock import exclusive_profile_lock
        calls=[]
        api=SimpleNamespace(LK_NBLCK=2,LK_UNLCK=0,locking=lambda *args:calls.append(args))
        with patch.dict('sys.modules',{'msvcrt':api}),patch('wec_wips.profile_lock.sys.platform','win32'):
            with exclusive_profile_lock(self.store.directory):pass
        self.assertEqual([c[1:] for c in calls],[(2,1),(0,1)])

if __name__=='__main__': unittest.main()
