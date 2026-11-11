import csv
import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wec_wips.core import Result


def result(ip='192.0.2.10', status='IP일치', **kwargs):
    row=Result('2026-11-11T16:00:00+09:00', ip, status, mode='verify_ip',
               target_ip='198.51.100.20', after_ip='198.51.100.20', ip_check='일치')
    row.summary_before='wips server ip : 198.51.100.20\nwips nat : 1\nwips sharedkey : [MASKED]'
    row.summary_after=''
    row.wips_mode='WIPS_SENSOR_MODE'
    for name,value in kwargs.items(): setattr(row,name,value)
    return row


def payload(document):
    match=re.search(r'<script[^>]+id=[\"\']report-data[\"\'][^>]*>(.*?)</script>',document,re.S)
    if not match: raise AssertionError('report-data JSON block missing')
    return json.loads(match.group(1))


class ReportTests(unittest.TestCase):
    def test_report_module_exists(self):
        self.assertIsNotNone(importlib.util.find_spec('wec_wips.reports'))

    def test_rows_allowlist_ignores_credentials_and_raw_transcript(self):
        from wec_wips.reports import report_rows
        row=result();row.password='NEVER_PASSWORD';row.shared_key='NEVER_KEY';row.raw='NEVER_RAW'
        values=report_rows([row])
        text=json.dumps(values,ensure_ascii=False)
        self.assertNotIn('NEVER_',text)
        self.assertEqual(values[0]['ap_ip'],'192.0.2.10')
        self.assertEqual(values[0]['category'],'match')
        self.assertNotIn('password',values[0])

    def test_categories_keep_ip_comparison_separate_from_partial_verification(self):
        from wec_wips.reports import report_rows
        rows=report_rows([result(status='부분확인'),result(status='검증불일치'),
                         result(status='실패'),result(status='미실행'),
                         result(status='IP불일치',ip_check='불일치'),
                         result(status='조회완료',ip_check='')])
        self.assertEqual([r['category'] for r in rows],['match','match','failed','unexecuted','mismatch','unknown'])
        self.assertTrue(rows[0]['attention'])
        self.assertTrue(rows[1]['attention'])

    def test_script_payload_escape_and_unicode_roundtrip(self):
        from wec_wips.reports import render_html
        attack='</script><script>window.PWN=1</script>&\u2028\u2029'
        html=render_html([result(message=attack)],title='<보고서 & 1>')
        data=payload(html)
        self.assertEqual(data['title'],'<보고서 & 1>')
        self.assertEqual(data['rows'][0]['message'],attack)
        self.assertNotIn('<script>window.PWN=1',html)
        self.assertIn('&lt;보고서 &amp; 1&gt;',html)
        self.assertNotIn('\u2028',html)
        self.assertNotIn('\u2029',html)

    def test_bundle_contains_csv_and_report_with_all_statuses_and_bom(self):
        from wec_wips.reports import write_report_bundle
        items=[result(),result('192.0.2.11','IP불일치',ip_check='불일치'),result('192.0.2.12','미실행',ip_check='')]
        with tempfile.TemporaryDirectory() as d:
            folder=write_report_bundle(d,items)
            self.assertTrue(folder.is_dir())
            data=payload((folder/'report.html').read_text('utf-8'))
            self.assertEqual(data['counts'],dict(total=3,match=1,mismatch=1,failed=0,unexecuted=1,unknown=0))
            raw=(folder/'results.csv').read_bytes()
            self.assertTrue(raw.startswith(b'\xef\xbb\xbf'))
            with (folder/'results.csv').open(encoding='utf-8-sig') as f: rows=list(csv.DictReader(f))
            self.assertEqual([r['ap_ip'] for r in rows],[r.ap_ip for r in items])
            self.assertIn('summary_before',rows[0])

    def test_bundle_write_failure_leaves_no_incomplete_report(self):
        from wec_wips.reports import write_report_bundle
        with tempfile.TemporaryDirectory() as d:
            keep=Path(d)/'keep.txt';keep.write_text('keep')
            with patch('wec_wips.reports.export_results',side_effect=OSError('disk full')) as exporter:
                with self.assertRaises(OSError):write_report_bundle(d,[result()])
                exporter.assert_called_once()
            self.assertEqual([p.name for p in Path(d).iterdir()],['keep.txt'])

    def test_text_keeps_requested_shared_key_but_excludes_unknown_raw(self):
        from wec_wips.reports import export_ap_txt
        row=result(summary_before='banner NEVER_BANNER\nconfig wips server 198.51.100.20 NEVER_ECHO\nwips server ip : 198.51.100.20\nwips sharedkey : SYNTHETIC_WIPS_KEY\nunknown: NEVER_UNKNOWN')
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'detail.txt';export_ap_txt(target,row)
            text=target.read_text('utf-8-sig')
            self.assertIn('198.51.100.20',text)
            self.assertIn('SYNTHETIC_WIPS_KEY',text)
            for secret in ('NEVER_BANNER','NEVER_ECHO','NEVER_UNKNOWN'):
                self.assertNotIn(secret,text)
            self.assertTrue(target.read_bytes().startswith(b'\xef\xbb\xbf'))

    def test_selected_txts_only_unique_names_and_no_overwrite(self):
        from wec_wips.reports import export_ap_txts
        with tempfile.TemporaryDirectory() as d:
            chosen=[result(),result('192.0.2.10')]
            first=export_ap_txts(d,chosen);second=export_ap_txts(d,chosen)
            self.assertNotEqual(first,second)
            files=list((first/'details').glob('*.txt'))
            self.assertEqual(len(files),2)
            self.assertEqual({p.name for p in files},{'192.0.2.10.txt','192.0.2.10_2.txt'})
            self.assertFalse((first/'details'/'192.0.2.11.txt').exists())

    def test_malicious_filename_ip_is_rejected_before_creating_folder(self):
        from wec_wips.reports import export_ap_txts
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):export_ap_txts(d,[result('../../escape')])
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_empty_report_has_zero_counts(self):
        from wec_wips.reports import render_html
        data=payload(render_html([]))
        self.assertEqual(data['rows'],[])
        self.assertEqual(sum(data['counts'].values()),0)

    def test_ten_thousand_rows_use_json_not_static_table_rows(self):
        from wec_wips.reports import render_html
        rows=[result(f'10.0.{i//256}.{i%256}') for i in range(10000)]
        document=render_html(rows)
        self.assertEqual(len(payload(document)['rows']),10000)
        self.assertLess(document.count('<tr'),10)
        self.assertLess(len(document),20_000_000)

    def test_single_txt_atomic_failure_preserves_previous_file(self):
        from wec_wips.reports import export_ap_txt
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'detail.txt';target.write_text('previous')
            with patch('wec_wips.reports.os.replace',side_effect=OSError('write failure')):
                with self.assertRaises(OSError):export_ap_txt(target,result())
            self.assertEqual(target.read_text(),'previous')
            self.assertEqual([p.name for p in Path(d).iterdir()],['detail.txt'])

    def test_csv_formula_message_is_escaped(self):
        from wec_wips.reports import write_report_bundle
        with tempfile.TemporaryDirectory() as d:
            folder=write_report_bundle(d,[result(message='=1+1')])
            with (folder/'results.csv').open(encoding='utf-8-sig') as f: rows=list(csv.DictReader(f))
            self.assertEqual(rows[0]['message'],"'=1+1")

    def test_title_with_template_token_is_not_expanded(self):
        from wec_wips.reports import render_html
        template='<title>__REPORT_TITLE__</title><script id="report-data" type="application/json">__REPORT_DATA__</script>'
        with patch('wec_wips.reports.Path.read_text',return_value=template):
            document=render_html([],title='__REPORT_DATA__ title')
        self.assertIn('<title>__REPORT_DATA__ title</title>',document)
        self.assertEqual(payload(document)['title'],'__REPORT_DATA__ title')

    def test_hostname_and_observed_time_in_html_csv_and_txt(self):
        from wec_wips.reports import write_report_bundle, export_ap_txt
        row=result(status='실패', hostname='우면-F타워-AP01', hostname_source='CSV',
                   observed_at='2026-11-11T16:23:00+09:00')
        with tempfile.TemporaryDirectory() as d:
            folder=write_report_bundle(d,[row])
            data=payload((folder/'report.html').read_text('utf-8'))['rows'][0]
            self.assertEqual(data['hostname'],'우면-F타워-AP01')
            self.assertEqual(data['hostname_source'],'CSV')
            self.assertEqual(data['observed_at'],'2026-11-11T16:23:00+09:00')
            with (folder/'results.csv').open(encoding='utf-8-sig') as f: csvrow=next(csv.DictReader(f))
            self.assertEqual(csvrow['hostname'],'우면-F타워-AP01')
            txt=folder/'selected.txt';export_ap_txt(txt,row)
            text=txt.read_text('utf-8-sig')
            self.assertIn('우면-F타워-AP01',text)
            self.assertIn('CSV',text)
            self.assertIn('2026-11-11T16:23:00+09:00',text)

    def test_hostname_is_escaped_and_never_used_for_filename(self):
        from wec_wips.reports import render_html, export_ap_txts
        attack='../../<script>window.HOST=1</script>'
        row=result(hostname=attack,hostname_source='CSV',observed_at='')
        document=render_html([row])
        self.assertEqual(payload(document)['rows'][0]['hostname'],attack)
        self.assertNotIn('<script>window.HOST=1',document)
        with tempfile.TemporaryDirectory() as d:
            folder=export_ap_txts(d,[row])
            self.assertEqual([p.name for p in (folder/'details').iterdir()],['192.0.2.10.txt'])

    def test_unexecuted_hostname_retained(self):
        from wec_wips.reports import report_rows
        rows=report_rows([result(status='미실행',hostname='미처리-AP',hostname_source='CSV')])
        self.assertEqual(rows[0]['hostname'],'미처리-AP')
        self.assertEqual(rows[0]['category'],'unexecuted')

    def test_device_shared_key_exported_in_html_csv_and_both_txt_paths(self):
        from wec_wips.reports import write_report_bundle, export_ap_txt, export_ap_txts
        key='Demo<key>&"' + "'" + '2026'
        row=result(summary_before=f'wips server ip : 198.51.100.20\nwips sharedkey : {key}')
        with tempfile.TemporaryDirectory() as d:
            folder=write_report_bundle(d,[row])
            document=(folder/'report.html').read_text('utf-8')
            data=payload(document)
            self.assertIn(key,data['rows'][0]['summary_before'])
            self.assertEqual(data['version'],'1.5.1')
            self.assertNotIn('<key>',document)
            with (folder/'results.csv').open(encoding='utf-8-sig') as f: csvrow=next(csv.DictReader(f))
            self.assertIn(key,csvrow['summary_before'])
            single=folder/'single.txt';export_ap_txt(single,row)
            self.assertIn(key,single.read_text('utf-8-sig'))
            selected=export_ap_txts(d,[row])
            self.assertIn(key,(selected/'details'/'192.0.2.10.txt').read_text('utf-8-sig'))
            self.assertNotIn('공유키 제외',single.read_text('utf-8-sig'))

    def test_device_masked_value_cannot_be_reconstructed(self):
        from wec_wips.reports import report_rows
        row=result(summary_before='wips server ip : 198.51.100.20\nwips sharedkey : ********')
        text=report_rows([row])[0]['summary_before']
        self.assertNotIn('DemoKey',text)
        self.assertIn('********',text)

    def test_raw_key_control_and_oversize_values_not_exported(self):
        from wec_wips.reports import report_rows
        for key in ('SECRET'+'X'*300, 'SECRET\x01CONTROL'):
            row=result(summary_before=f'wips server ip : 198.51.100.20\nwips sharedkey : {key}')
            text=report_rows([row])[0]['summary_before']
            self.assertNotIn(key,text)
            self.assertNotIn('SECRET',text)


if __name__=='__main__':unittest.main()
