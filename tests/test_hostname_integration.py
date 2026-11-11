import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_integration
from wec_wips.core import RunConfig
from wec_wips.reports import write_report_bundle, export_ap_txts


class HostnameReportIntegrationTests(unittest.TestCase):
    def test_controller_names_reach_all_reports_over_real_telnet(self):
        harness = test_integration.TelnetIntegrationTests()
        def configured(**kwargs):
            return RunConfig(**kwargs, lookup_hostnames=True)
        with patch('test_integration.RunConfig', side_effect=configured):
            results, commands, _, _, _ = harness._run_job(
                mode='verify_ip', ap_ips=['192.0.2.10', '192.0.2.11'],
                server_ip='192.0.2.200', shared_key='')
        self.assertEqual([r.hostname for r in results], ['LAB-AP10', 'LAB-AP11'])
        self.assertEqual([r.hostname_source for r in results], ['컨트롤러 AP_NAME'] * 2)
        self.assertTrue(all(r.observed_at for r in results))
        self.assertEqual(sum(line == 'show ap summary' for _, line in commands), 1)
        self.assertEqual(sum(line == 'show config wips summary' for _, line in commands), 2)
        self.assertFalse(any(line.startswith('config ') for _, line in commands))
        with tempfile.TemporaryDirectory() as d:
            report = write_report_bundle(d, results)
            details = export_ap_txts(d, results[1:])
            self.assertIn('LAB-AP11', (report / 'report.html').read_text())
            with (report / 'results.csv').open(encoding='utf-8-sig') as f:
                self.assertEqual([r['hostname'] for r in csv.DictReader(f)], ['LAB-AP10', 'LAB-AP11'])
            self.assertEqual(len(list((details / 'details').glob('*.txt'))), 1)
            txt = (details / 'details/192.0.2.11.txt').read_text('utf-8-sig')
            self.assertIn('LAB-AP11', txt)
            self.assertIn('wips sharedkey : OldIntegrationKey', txt)


if __name__ == '__main__': unittest.main()
