"""Operator exports carry device keys; diagnostics still omit secret values."""
import csv
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_integration
from wec_wips.core import RunConfig, export_results
from wec_wips.gui import WipsApp
from wec_wips.journal import LocalJournal
from wec_wips.reports import write_report_bundle, export_ap_txts


class SharedKeyIntegrationTests(unittest.TestCase):
    def test_queried_key_reaches_details_and_every_operator_export(self):
        results, commands, _, _, _ = test_integration.TelnetIntegrationTests()._run_job(
            mode='verify_ip', server_ip='192.0.2.200', shared_key='')
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertIn('wips sharedkey : OldIntegrationKey', result.summary_before)
        self.assertFalse(any(line.startswith('config ') for _, line in commands))
        app = object.__new__(WipsApp)
        app.results, app.root = results, None
        app.table = SimpleNamespace(selection=lambda: ('0',))
        with patch('wec_wips.gui.messagebox.showinfo') as dialog:
            app._result_details()
        self.assertIn('wips sharedkey : OldIntegrationKey', dialog.call_args.args[1])
        with tempfile.TemporaryDirectory() as d:
            folder = write_report_bundle(d, results)
            details = export_ap_txts(d, results)
            direct = Path(d) / 'direct.csv'
            export_results(direct, results)
            self.assertIn('OldIntegrationKey', (folder / 'report.html').read_text())
            self.assertIn('wips sharedkey : OldIntegrationKey',
                          (details / 'details/192.0.2.10.txt').read_text('utf-8-sig'))
            for filename in (folder / 'results.csv', direct):
                with filename.open(encoding='utf-8-sig', newline='') as f:
                    self.assertIn('wips sharedkey : OldIntegrationKey',
                                  next(csv.DictReader(f))['summary_before'])

    def test_change_retains_actual_before_after_keys_but_diagnostics_mask_both(self):
        results, _, _, _, _ = test_integration.TelnetIntegrationTests()._run_job()
        result = results[0]
        self.assertEqual(result.status, '변경확인')
        self.assertIn('wips sharedkey : OldIntegrationKey', result.summary_before)
        self.assertIn('wips sharedkey : NewIntegrationKey', result.summary_after)
        cfg = RunConfig('192.0.2.1', 23, 'operator', 'ControllerIntegrationSecret',
                        ['192.0.2.10'], 50022, 'root', 'APIntegrationSecret',
                        server_ip='198.51.100.20', shared_key='NewIntegrationKey')
        with tempfile.TemporaryDirectory() as d:
            journal = LocalJournal(cfg, 'apply', base_dir=d)
            journal.record('result', {'result': result})
            journal.close()
            diagnostic = '\n'.join(p.read_text('utf-8-sig') for p in journal.directory.iterdir())
            self.assertNotIn('IntegrationKey', diagnostic)
            self.assertNotIn('IntegrationSecret', diagnostic)
            self.assertIn('[MASKED]', diagnostic)
            report = write_report_bundle(d, results)
            with (report / 'results.csv').open(encoding='utf-8-sig', newline='') as f:
                row = next(csv.DictReader(f))
            self.assertIn('OldIntegrationKey', row['summary_before'])
            self.assertIn('NewIntegrationKey', row['summary_after'])


if __name__ == '__main__':
    unittest.main()
