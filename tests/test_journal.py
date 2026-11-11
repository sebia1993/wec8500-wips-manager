import csv
import json
import tempfile
import unittest
from pathlib import Path

from wec_wips.core import RunConfig, Result


class JournalTests(unittest.TestCase):
    def test_safe_report_fields_and_hostname_are_retained_without_keys(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            r=Result('2026-11-11T15:00:00+09:00','192.0.2.10','IP일치',mode='verify_ip')
            r.hostname='LAB-3F-AP01';r.hostname_source='CSV'
            r.observed_at='2026-11-11T15:01:02+09:00'
            r.summary_before='wips server ip : 198.51.100.20\nwips nat : 2\nwips sharedkey : NEVER_OLD_KEY'
            r.wips_mode='WIPS_SENSOR_MODE'
            j.record('result',{'result':r});j.close()
            with (j.directory/'results.csv').open(encoding='utf-8-sig') as f:
                row=next(csv.DictReader(f))
            self.assertEqual(row.get('hostname'),'LAB-3F-AP01')
            self.assertEqual(row.get('hostname_source'),'CSV')
            self.assertEqual(row.get('observed_at'),r.observed_at)
            self.assertIn('[MASKED]',row['summary_before'])
            self.assertNotIn('NEVER_', '\n'.join(p.read_text('utf-8-sig') for p in j.directory.iterdir()))

    def test_hostname_cannot_record_a_configured_password(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            r=Result('2026-11-11','192.0.2.10','미실행',mode='apply')
            r.hostname='NEVER_CONTROLLER';r.hostname_source='CSV'
            j.record('result',{'result':r});j.close()
            self.assertNotIn('NEVER_', '\n'.join(p.read_text('utf-8-sig') for p in j.directory.iterdir()))

    def config(self):
        return RunConfig('192.0.2.1',23,'operator','NEVER_CONTROLLER',
                         ['192.0.2.10'],50022,'root','NEVER_AP',
                         server_ip='198.51.100.20',shared_key='NEVER_KEY')

    def test_journal_available(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('wec_wips.journal'))

    def make(self, folder):
        from wec_wips.journal import LocalJournal
        return LocalJournal(self.config(),'apply',base_dir=Path(folder))

    def test_records_stages_and_results_without_credentials_or_raw_messages(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            j.record('stage',{'ap_ip':'192.0.2.10','stage':'사전 조회','attempt':1,
                              'password':'NEVER_EVENT'})
            j.record('log',{'message':'NEVER_RAW_PROMPT NEVER_KEY'})
            r=Result('2026-11-11T15:00:00+09:00','192.0.2.10','확인불가',
                     before_ip='192.0.2.100',message='NEVER_REMOTE_EXCEPTION',mode='apply')
            j.record('result',{'result':r})
            j.record('done',{'cancelled':False})
            j.close()
            contents='\n'.join(p.read_text('utf-8-sig') for p in j.directory.iterdir())
            self.assertNotIn('NEVER_',contents)
            self.assertIn('192.0.2.10',contents)
            events=[json.loads(x) for x in (j.directory/'events.jsonl').read_text().splitlines()]
            self.assertTrue(any(x.get('stage')=='사전 조회' for x in events))
            with (j.directory/'results.csv').open(encoding='utf-8-sig') as f:
                rows=list(csv.DictReader(f))
            self.assertEqual(rows[0]['status'],'확인불가')
            self.assertEqual(rows[0]['message'],'')
            self.assertFalse(json.loads((j.directory/'state.json').read_text())['running'])

    def test_retry_and_activity_sanitized(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            j.record('retry',{'ap_ip':'192.0.2.10','attempt':2,'max_attempts':3,
                              'delay':3,'error_code':'COMMAND_TIMEOUT', 'response':'NEVER_RAW'})
            for _ in range(50):j.record('activity',{'ap_ip':'192.0.2.10','bytes':'NEVER_BYTES'})
            j.close()
            text=(j.directory/'events.jsonl').read_text()
            self.assertNotIn('NEVER',text)
            self.assertIn('COMMAND_TIMEOUT',text)
            self.assertLess(len(text.splitlines()),10)

    def test_invalid_untrusted_result_fields_filtered(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            r=Result('NEVER_TIME','NEVER_IP','NEVER_STATUS',message='NEVER_MESSAGE',
                     before_ip='NEVER_IP',key_check='NEVER_KEY',mode='NEVER_MODE')
            j.record('result',{'result':r})
            j.record('stage',{'ap_ip':'NEVER_IP','stage':'NEVER_STAGE'})
            j.close()
            self.assertNotIn('NEVER', '\n'.join(p.read_text('utf-8-sig') for p in j.directory.iterdir()))

    def test_close_idempotent_and_unique_directory(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d); j2=self.make(d)
            self.assertNotEqual(j.directory,j2.directory)
            j.close();j.close();j2.close()

    def test_state_update_is_atomic_and_does_not_leave_temp(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            j.record('stage',{'ap_ip':'192.0.2.10','stage':'변경 명령','attempt':1})
            state=json.loads((j.directory/'state.json').read_text())
            self.assertTrue(state['running']);self.assertEqual(state['stage'],'변경 명령')
            self.assertFalse(list(j.directory.glob('*.tmp')))
            j.close()

    def test_runner_failure_codes_preserved(self):
        from wec_wips.journal import ERROR_CODES
        expected = {'PREPARE_FAILED', 'SUMMARY_INVALID', 'CLI_REJECTED',
                    'RECOVERY_UNVERIFIABLE', 'VERIFICATION_PARTIAL', 'VERIFICATION_MISMATCH'}
        self.assertTrue(expected <= ERROR_CODES)
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            for code in expected:
                r=Result('2026-11-11','192.0.2.10','확인불가',mode='apply')
                r.error_code=code
                j.record('result',{'result':r})
            j.close()
            with (j.directory/'results.csv').open(encoding='utf-8-sig') as f:
                self.assertEqual({row['error_code'] for row in csv.DictReader(f)},expected)

    def test_close_without_done_marks_abnormal_end(self):
        with tempfile.TemporaryDirectory() as d:
            j=self.make(d)
            j.record('stage',{'ap_ip':'192.0.2.10','stage':'변경 명령','attempt':1})
            j.close()
            state=json.loads((j.directory/'state.json').read_text())
            self.assertFalse(state['running'])
            self.assertEqual(state['outcome'],'ended_before_done')
            self.assertEqual(state['stage'],'변경 명령')
