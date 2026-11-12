"""Portable handoff plumbing, not native Windows encryption validation."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class WindowsRunnerTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / 'tools/windows_validation_runner.py'
        self.assertTrue(source.is_file(), 'portable runner has not been implemented')
        spec = importlib.util.spec_from_file_location('portable_runner_test', source)
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self):
        files = {}
        for name in self.runner.MANDATORY:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'known fixture data')
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        document = {'schema': 1, 'application_build': 'profile.4', 'files': files}
        (self.root / 'VALIDATION_MANIFEST.json').write_text(json.dumps(document))
        return document

    def test_matching_files_are_checked_without_executing_product(self):
        self.bundle()
        result = self.runner.verify_bundle(self.root)
        self.assertEqual(result, {'status': 'PASS', 'files_checked': len(self.runner.MANDATORY)})

    def test_tampered_file_does_not_pass_integrity(self):
        self.bundle(); (self.root/'python.exe').write_bytes(b'tampered')
        with self.assertRaises(self.runner.CheckError) as error: self.runner.verify_bundle(self.root)
        self.assertEqual(error.exception.code, 'BUNDLE_MISMATCH')

    def test_missing_file_does_not_pass_integrity(self):
        self.bundle(); (self.root/'python.exe').unlink()
        with self.assertRaises(self.runner.CheckError): self.runner.verify_bundle(self.root)

    def test_empty_manifest_cannot_claim_matching_bundle(self):
        doc=self.bundle(); doc['files']={}
        (self.root/'VALIDATION_MANIFEST.json').write_text(json.dumps(doc))
        with self.assertRaises(self.runner.CheckError): self.runner.verify_bundle(self.root)

    def test_path_traversal_and_absolute_paths_are_rejected(self):
        for name in ('../private', '/private', 'C:/private', 'x\\private'):
            with self.subTest(name=name):
                doc=self.bundle(); doc['files'][name]='0'*64
                (self.root/'VALIDATION_MANIFEST.json').write_text(json.dumps(doc))
                with self.assertRaises(self.runner.CheckError): self.runner.verify_bundle(self.root)

    def test_symlink_payload_is_rejected(self):
        self.bundle(); target=self.root/'python.exe'; target.unlink()
        target.symlink_to(self.root/'python313.dll')
        with self.assertRaises(self.runner.CheckError): self.runner.verify_bundle(self.root)

    def suite(self, bad=None):
        methods={}
        for name in self.runner.CASES:
            def check(case, name=name):
                if name==bad: raise RuntimeError('PRIVATE_USERNAME PASSWORD SECRET_PATH')
            methods[name]=check
        cls=type('SyntheticChecks',(unittest.TestCase,),methods)
        return unittest.defaultTestLoader.loadTestsFromTestCase(cls)

    def test_exact_six_successes_produce_native_pass_but_not_stage9_completion(self):
        result=self.runner.run_suite(self.suite())
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['tests_run'],6)
        self.assertFalse(result['stage9_complete'])

    def test_error_report_contains_no_exception_text_or_traceback(self):
        result=self.runner.run_suite(self.suite(bad=next(iter(self.runner.CASES))))
        self.assertEqual(result['status'],'FAIL')
        text=json.dumps(result)
        for secret in ('PRIVATE_USERNAME','PASSWORD','SECRET_PATH','Traceback'):
            self.assertNotIn(secret,text)

    def test_empty_or_incomplete_suite_cannot_pass(self):
        result=self.runner.run_suite(unittest.TestSuite())
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['tests_run'],0)

    def test_skipped_check_cannot_pass(self):
        suite=self.suite()
        suite._tests[0].setUp=lambda: (_ for _ in ()).throw(unittest.SkipTest('PRIVATE_SKIP_REASON'))
        result=self.runner.run_suite(suite)
        self.assertEqual(result['status'],'FAIL')
        self.assertNotIn('PRIVATE_SKIP_REASON',json.dumps(result))

    def test_nonwindows_is_not_run_and_does_not_read_live_profile(self):
        if sys.platform=='win32': self.skipTest('negative host check is for non-Windows')
        with self.assertRaises(self.runner.CheckError) as error: self.runner.require_windows(self.root)
        self.assertEqual(error.exception.code,'WINDOWS_REQUIRED')
        self.assertFalse(list(self.root.iterdir()))

    def test_report_is_new_file_without_raw_local_paths(self):
        report=self.runner.failure_report('CHECK_TIMEOUT')
        self.runner.write_json(self.root/'result.json',report)
        text=(self.root/'result.json').read_text()
        self.assertNotIn(str(self.root),text)
        self.assertEqual(json.loads(text)['status'],'NOT_COMPLETED')
        self.assertFalse(json.loads(text)['stage9_complete'])


    def test_supervisor_timeout_is_not_completed_without_private_details(self):
        with patch.object(self.runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired('PRIVATE_COMMAND', 180)):
            result=self.runner.supervise(self.root,self.root/'native.json')
        self.assertEqual(result['error_code'],'CHECK_TIMEOUT')
        self.assertEqual(result['status'],'NOT_COMPLETED')
        self.assertNotIn('PRIVATE_COMMAND',json.dumps(result))

    def test_supervisor_missing_result_cannot_be_success(self):
        with patch.object(self.runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            result=self.runner.supervise(self.root,self.root/'missing.json')
        self.assertNotEqual(result['status'],'PASS')

    def test_supervisor_incomplete_pass_is_rejected(self):
        doc=self.runner.run_suite(self.suite());doc['checks']=doc['checks'][:1]
        path=self.root/'native.json';path.write_text(json.dumps(doc))
        with patch.object(self.runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            result=self.runner.supervise(self.root,path)
        self.assertEqual(result['error_code'],'RESULT_INVALID')

    def test_supervisor_does_not_propagate_arbitrary_report_metadata(self):
        doc=self.runner.run_suite(self.suite());doc.update(scope='PRIVATE_USER_PATH',
            manual_windows_ui_account_reboot_checks='PRIVATE_MESSAGE',extra='PRIVATE_KEY')
        path=self.root/'native.json';path.write_text(json.dumps(doc))
        with patch.object(self.runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
            result=self.runner.supervise(self.root,path)
        self.assertNotIn('PRIVATE_',json.dumps(result))
        self.assertEqual(result['manual_windows_ui_account_reboot_checks'],'PENDING')

    def test_failed_process_cannot_be_overridden_by_pass_file(self):
        doc=self.runner.run_suite(self.suite());path=self.root/'native.json';path.write_text(json.dumps(doc))
        with patch.object(self.runner.subprocess, 'run', return_value=SimpleNamespace(returncode=3)):
            result=self.runner.supervise(self.root,path)
        self.assertNotEqual(result['status'],'PASS')

if __name__=='__main__': unittest.main()
