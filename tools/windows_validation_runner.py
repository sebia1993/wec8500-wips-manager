"""Offline stage-9 handoff supervisor, not a device-management entry point.

Use the bundled CMD. Native checks run only on Windows, against synthetic
profiles in TemporaryDirectory. Reports deliberately exclude exception text,
tracebacks, account names, machine names and local paths. No product edits.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

BUILD = 'profile.4'
CASES = {
    'test_native_roundtrip_new_store_instance': 'DPAPI save / reload',
    'test_native_entropy_binding': 'Endpoint binding',
    'test_native_corruption_fails_closed': 'Damaged ciphertext rejected',
    'test_native_update_and_delete': 'Update / delete',
    'test_native_stale_window_cannot_revert_or_delete_new_secrets': 'Stale write / delete rejected',
    'test_native_lock_excludes_a_second_process': 'Cross-process Windows lock',
}
MANDATORY = (
    'python.exe', 'python313.dll', 'wec_wips/dpapi.py',
    'wec_wips/profile_store.py', 'wec_wips/profile_lock.py',
    'tests/windows_profile_check.py', 'tools/windows_validation_runner.py',
)
CODES = frozenset(('WINDOWS_REQUIRED', 'PACKAGED_RUNTIME_REQUIRED', 'X64_REQUIRED',
    'BUNDLE_INVALID', 'BUNDLE_MISSING', 'BUNDLE_MISMATCH', 'CHECK_TIMEOUT',
    'CHECK_PROCESS_FAILED', 'RESULT_INVALID', 'CHECK_ERROR', 'REPORT_WRITE_FAILED',
    'ASSERTION_FAILED', 'OS_ERROR', 'CHILD_TIMEOUT', 'SKIPPED', 'UNEXPECTED_TEST'))


class CheckError(RuntimeError):
    def __init__(self, code):
        self.code = code if code in CODES else 'CHECK_ERROR'
        super().__init__(self.code)


def require_windows(root):
    if sys.platform != 'win32':
        raise CheckError('WINDOWS_REQUIRED')
    if Path(sys.executable).resolve() != (Path(root) / 'python.exe').resolve():
        raise CheckError('PACKAGED_RUNTIME_REQUIRED')
    if struct.calcsize('P') != 8:
        raise CheckError('X64_REQUIRED')


def verify_bundle(root):
    """Detect missing/modified deliverable files; not a digital signature."""
    root = Path(root).resolve()
    try:
        with (root/'VALIDATION_MANIFEST.json').open('rb') as stream:
            manifest = stream.read(2*1024*1024+1)
        if len(manifest) > 2*1024*1024:
            raise CheckError('BUNDLE_INVALID')
        doc = json.loads(manifest)
        if (not isinstance(doc, dict) or doc.get('schema') != 1
                or doc.get('application_build') != BUILD
                or not isinstance(doc.get('files'), dict)
                or not set(MANDATORY).issubset(doc['files'])):
            raise CheckError('BUNDLE_INVALID')
        for name, digest in doc['files'].items():
            rel = PurePosixPath(name)
            if (rel.is_absolute() or not name or '..' in rel.parts or '.' in rel.parts
                    or '\\' in name or ':' in name or str(rel) != name
                    or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
                raise CheckError('BUNDLE_INVALID')
            path = root
            for part in rel.parts:
                path = path/part
                if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                    raise CheckError('BUNDLE_INVALID')
            if not path.is_file():
                raise CheckError('BUNDLE_MISSING')
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise CheckError('BUNDLE_MISMATCH')
        return {'status': 'PASS', 'files_checked': len(doc['files'])}
    except CheckError:
        raise
    except Exception:
        raise CheckError('BUNDLE_INVALID') from None


class SafeResult(unittest.TestResult):
    """Never retain traceback formatting or arbitrary exception/skip messages."""
    def __init__(self):
        super().__init__()
        self.rows = []

    def startTest(self, test):
        super().startTest(test)
        name = getattr(test, '_testMethodName', '')
        self.rows.append({'check': name if name in CASES else 'UNEXPECTED_TEST',
                          'status': 'RUNNING', 'error_code': ''})

    def addSuccess(self, test):
        self.rows[-1]['status'] = 'PASS'

    def _bad(self, status, code):
        self.rows[-1].update(status=status, error_code=code)

    def addFailure(self, test, err):
        self.failures.append((None, 'ASSERTION_FAILED'))
        self._bad('FAIL', 'ASSERTION_FAILED')

    def addError(self, test, err):
        exc = err[1]
        code = ('CHILD_TIMEOUT' if isinstance(exc, subprocess.TimeoutExpired)
                else 'OS_ERROR' if isinstance(exc, OSError) else 'CHECK_ERROR')
        self.errors.append((None, code))
        self._bad('FAIL', code)

    def addSkip(self, test, reason):
        self.skipped.append((None, 'SKIPPED'))
        self._bad('SKIP', 'SKIPPED')

    def addUnexpectedSuccess(self, test):
        self.unexpectedSuccesses.append(None)
        self._bad('FAIL', 'UNEXPECTED_TEST')

    def addExpectedFailure(self, test, err):
        self.expectedFailures.append((None, 'UNEXPECTED_TEST'))
        self._bad('FAIL', 'UNEXPECTED_TEST')


def run_suite(suite):
    result = SafeResult()
    suite.run(result)
    rows = result.rows
    complete = (result.testsRun == len(CASES) == len(rows)
                and {r['check'] for r in rows} == set(CASES)
                and all(r['status'] == 'PASS' for r in rows))
    return {'schema': 1, 'application_build': BUILD,
            'scope': 'SYNTHETIC_WINDOWS_PROTECTION_CHECKS',
            'status': 'PASS' if complete else 'FAIL',
            'tests_run': result.testsRun, 'expected_tests': len(CASES),
            'checks': rows, 'stage9_complete': False,
            'manual_windows_ui_account_reboot_checks': 'PENDING',
            'equipment_validation': 'PENDING'}


def failure_report(code):
    code = code if code in CODES else 'CHECK_ERROR'
    return {'schema': 1, 'application_build': BUILD,
            'scope': 'SYNTHETIC_WINDOWS_PROTECTION_CHECKS',
            'status': 'NOT_RUN' if code == 'WINDOWS_REQUIRED' else 'NOT_COMPLETED',
            'error_code': code, 'tests_run': 0, 'expected_tests': len(CASES),
            'checks': [], 'stage9_complete': False,
            'manual_windows_ui_account_reboot_checks': 'PENDING',
            'equipment_validation': 'PENDING'}


def write_json(path, document):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8', newline='\n') as handle:
            json.dump(document, handle, ensure_ascii=True, indent=2)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def child_main(root, destination):
    """This is a separate process; it cannot auto-start the application GUI."""
    require_windows(root)
    verify_bundle(root)
    destination = Path(destination).resolve()
    if (destination.name != 'native_results.json'
            or destination.parent.parent != (root/'results').resolve()
            or not destination.parent.name.startswith('WindowsCheck_')):
        raise CheckError('RESULT_INVALID')
    sys.path.insert(0, str(root))
    script = root/'tests/windows_profile_check.py'
    spec = importlib.util.spec_from_file_location('native_windows_profile_check', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.WindowsProfileChecks)
    document = run_suite(suite)
    write_json(destination, document)
    return 0 if document['status'] == 'PASS' else 1


def supervise(root, destination):
    env = dict(os.environ)
    # Child-of-child in the unchanged native lock test uses this environment.
    for name in tuple(env):
        if name.upper().startswith('PYTHON'):
            del env[name]
    env.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
    try:
        completed = subprocess.run(
            [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
             '--child', str(destination)], cwd=root, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    except subprocess.TimeoutExpired:
        return failure_report('CHECK_TIMEOUT')
    except OSError:
        return failure_report('CHECK_PROCESS_FAILED')
    try:
        raw = Path(destination).read_bytes()
        if len(raw) > 65536:
            raise CheckError('RESULT_INVALID')
        document = json.loads(raw)
        rows = document['checks']
        valid = (document.get('schema') == 1 and document.get('application_build') == BUILD
                 and document.get('expected_tests') == len(CASES)
                 and document.get('stage9_complete') is False
                 and type(document.get('tests_run')) is int and 0 <= document['tests_run'] <= len(CASES)
                 and isinstance(rows, list) and len(rows) <= len(CASES)
                 and all(isinstance(r, dict) and set(r) == {'check','status','error_code'}
                         and r['check'] in CASES and r['status'] in ('PASS','FAIL','SKIP','RUNNING')
                         and (not r['error_code'] or r['error_code'] in CODES) for r in rows))
        if not valid:
            raise CheckError('RESULT_INVALID')
        if document['status'] == 'PASS':
            if (completed.returncode != 0 or document['tests_run'] != len(CASES)
                    or len(rows) != len(CASES) or {r['check'] for r in rows} != set(CASES)
                    or any(r['status'] != 'PASS' for r in rows)):
                raise CheckError('RESULT_INVALID')
        elif document['status'] != 'FAIL' or completed.returncode != 1:
            raise CheckError('RESULT_INVALID')
        # Rebuild from explicit fields instead of propagating arbitrary JSON keys.
        return {'schema': 1, 'application_build': BUILD,
                'scope': 'SYNTHETIC_WINDOWS_PROTECTION_CHECKS',
                'status': document['status'], 'tests_run': document['tests_run'],
                'expected_tests': len(CASES), 'checks': rows, 'stage9_complete': False,
                'manual_windows_ui_account_reboot_checks': 'PENDING',
                'equipment_validation': 'PENDING'}
    except Exception:
        return failure_report('RESULT_INVALID' if completed.returncode in (0,1) else 'CHECK_PROCESS_FAILED')


def main():
    root = Path(__file__).resolve().parents[1]
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        try:
            return child_main(root, sys.argv[2])
        except BaseException:
            return 2
    if len(sys.argv) != 1:
        print('Unsupported arguments. Use RUN_WINDOWS_CHECK.cmd.')
        return 2
    try:
        require_windows(root)
    except CheckError as exc:
        print('NOT RUN: ' + exc.code)
        return 2
    print('WEC8500 profile.4 - six synthetic Windows checks')
    print('No device connection, real profile access or credential input.')
    try:
        (root/'results').mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        folder = Path(tempfile.mkdtemp(prefix='WindowsCheck_'+stamp+'_', dir=root/'results'))
    except OSError:
        print('NOT COMPLETED: REPORT_WRITE_FAILED. Extract into a writable folder.')
        return 2
    try:
        integrity = verify_bundle(root)
        document = supervise(root, folder/'native_results.json')
        document['bundle_integrity'] = integrity
    except CheckError as exc:
        document = failure_report(exc.code)
    document['run_utc'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    document['python_version'] = '.'.join(map(str, sys.version_info[:3]))
    document['pointer_bits'] = struct.calcsize('P')*8
    lines = ['WEC8500 profile.4 Windows protection check',
             'Native checks: '+document['status'],
             'Tests run: '+str(document['tests_run'])+' / 6']
    if document.get('error_code'):
        lines.append('Error code: '+document['error_code'])
    for row in document['checks']:
        lines.append(row['status']+' | '+CASES[row['check']]+' | '+row['error_code'])
    lines += ['', 'Stage 9: NOT COMPLETE (manual EXE/UI/reboot/account checks still required).',
              'Stage 10: NOT RUN (equipment checks are separate).',
              'No automatic upload. Share only RESULT.json or RESULT.txt after review.']
    try:
        write_json(folder/'RESULT.json', document)
        (folder/'RESULT.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    except OSError:
        print('NOT COMPLETED: REPORT_WRITE_FAILED')
        return 2
    print('\n'.join(lines))
    print('Results folder: results/'+folder.name)
    return 0 if document['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
