import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def destroy_test_root(root):
    # Each test creates its own Tcl interpreter; cancel scheduled polls before
    # destroying it so callbacks cannot survive into the next GUI test.
    for callback in root.tk.call('after', 'info'):
        root.after_cancel(callback)
    root.destroy()


class CsvImportTests(unittest.TestCase):
    def test_named_ip_column_ignores_credentials(self):
        from wec_wips.gui import csv_ip_text
        text = csv_ip_text('ap_ip,id,pw\n192.0.2.10,admin,SECRET\n192.0.2.11,a,b\n')
        self.assertEqual(text, '192.0.2.10\n192.0.2.11')

    def test_ip_header_case_and_whitespace(self):
        from wec_wips.gui import csv_ip_text
        self.assertEqual(csv_ip_text(' AP IP ,name\n192.0.2.10,AP01\n'), '192.0.2.10')

    def test_unknown_columns_fail_without_echoing_file_data(self):
        from wec_wips.gui import csv_ip_text
        with self.assertRaises(ValueError) as cm:
            csv_ip_text('password,user\nSECRET,admin\n')
        self.assertNotIn('SECRET', str(cm.exception))

    def test_duplicate_ip_columns_are_rejected(self):
        from wec_wips.gui import csv_ip_text
        with self.assertRaises(ValueError):
            csv_ip_text('ip,AP IP\n192.0.2.1,192.0.2.2\n')

    def test_decode_error_uses_fixed_error_message(self):
        from wec_wips.gui import WipsApp
        app = object.__new__(WipsApp)
        app.busy = False
        app.root = None
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'bad.csv'
            filename.write_bytes(b'ip,password\n\xff,SECRET')
            with patch('wec_wips.gui.filedialog.askopenfilename', return_value=str(filename)), patch('wec_wips.gui.messagebox.showerror') as error:
                app._load_csv()
            self.assertEqual(error.call_args.args[1], '파일을 읽을 수 없습니다. UTF-8 또는 CP949 CSV인지 확인하세요.')


class DialogQueueTests(unittest.TestCase):
    def make_app(self):
        from wec_wips.gui import WipsApp
        app = object.__new__(WipsApp)
        app.events = queue.Queue()
        app.stop_event = threading.Event()
        return app

    def test_worker_confirm_uses_queue_and_returned_response(self):
        app = self.make_app()
        result = []
        thread = threading.Thread(target=lambda: result.append(app._worker_confirm('Title', 'fingerprint')))
        thread.start()
        kind, data = app.events.get(timeout=1)
        self.assertEqual(kind, 'confirm')
        self.assertEqual(data['message'], 'fingerprint')
        data['answer'].append(True)
        data['ready'].set()
        thread.join(1)
        self.assertEqual(result, [True])

    def test_stop_unblocks_worker_confirmation(self):
        app = self.make_app()
        result = []
        thread = threading.Thread(target=lambda: result.append(app._worker_confirm('Title', 'fingerprint')))
        thread.start()
        app.events.get(timeout=1)
        app.stop_event.set()
        thread.join(1)
        self.assertEqual(result, [False])


class GuiSmokeTests(unittest.TestCase):
    def test_verify_ip_without_key_shows_match_and_mismatch_for_all_demo_aps(self):
        import tkinter as tk
        from wec_wips.gui import WipsApp
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        try:
            app = WipsApp(root)
            app._fill_demo()
            app.shared_key.set('')
            self.assertEqual(app.verify_button.cget('text'), '③ 서버 IP 일치 확인')
            with patch('wec_wips.gui.messagebox.askyesno', return_value=True) as confirms:
                for target, expected in [('192.0.2.200', 'IP일치'), ('198.51.100.99', 'IP불일치')]:
                    app.server_ip.set(target)
                    app._start('verify_ip')
                    deadline = time.monotonic() + 5
                    while app.busy and time.monotonic() < deadline:
                        root.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                    self.assertEqual([r.status for r in app.results], [expected] * 3)
                    self.assertTrue(all(r.target_ip == target and r.after_ip == '192.0.2.200' for r in app.results))
                    self.assertTrue(all(r.simulated for r in app.results))
                    self.assertEqual(app.shared_key.get(), '')
                    self.assertIn('모의', app.status.get())
                    self.assertIn('target_ip', app.table.cget('columns'))
                    for row in app.table.get_children():
                        self.assertTrue(app.table.set(row, 'status').startswith('[모의] '))
            self.assertFalse(any(call.args[0] == '변경 대상 확인' for call in confirms.call_args_list))
            app.server_ip.set('')
            with self.assertRaises(ValueError):
                app._snapshot('verify_ip')
        finally:
            destroy_test_root(root)

    def test_demo_gui_runs_inspect_then_apply_and_keeps_secrets_out_of_log(self):
        import tkinter as tk
        from wec_wips.gui import WipsApp
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        try:
            app = WipsApp(root)
            app._fill_demo()
            with patch('wec_wips.gui.messagebox.askyesno', return_value=True):
                for mode, expected in [('inspect', '조회완료'), ('apply', '변경확인')]:
                    app._start(mode)
                    deadline = time.monotonic() + 5
                    while app.busy and time.monotonic() < deadline:
                        root.update()
                        time.sleep(.01)
                    self.assertFalse(app.busy)
                    self.assertEqual([r.status for r in app.results], [expected] * 3)
                    self.assertEqual(len(app.table.get_children()), 3)
                    self.assertTrue(all(r.simulated for r in app.results))
            self.assertNotIn('DemoKey2026', app.log.get('1.0', 'end'))
            self.assertNotIn('DemoPassword', app.log.get('1.0', 'end'))
        finally:
            destroy_test_root(root)

    def test_resume_after_form_edit_uses_saved_target_and_keeps_completed_rows(self):
        import tkinter as tk
        from wec_wips.gui import WipsApp
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        try:
            app = WipsApp(root)
            app._fill_demo()
            app.server_ip.set('192.0.2.200')
            app.shared_key.set('')
            app._start('verify_ip')
            deadline = time.monotonic() + 5
            while app.busy and time.monotonic() < deadline:
                root.update(); time.sleep(.01)
            self.assertEqual([r.status for r in app.results], ['IP일치'] * 3)
            app.results[1].status = '미실행'
            app._set_busy(False)
            self.assertEqual(str(app.resume_button.cget('state')), 'normal')
            app.server_ip.set('invalid edited target')
            app.resume_button.invoke()
            deadline = time.monotonic() + 5
            while app.busy and time.monotonic() < deadline:
                root.update(); time.sleep(.01)
            self.assertFalse(app.busy)
            self.assertEqual(len(app.results), 3)
            self.assertEqual(len(app.table.get_children()), 3)
            self.assertTrue(all(r.target_ip == '192.0.2.200' for r in app.results))
            self.assertEqual([r.status for r in app.results], ['IP일치'] * 3)
            self.assertEqual(str(app.resume_button.cget('state')), 'disabled')
            self.assertIsNotNone(app.journal_folder)
            self.assertTrue((app.journal_folder / 'results.csv').is_file())
        finally:
            destroy_test_root(root)

    def test_gui_starts_masked_and_demo_enabled(self):
        import tkinter as tk
        from wec_wips.gui import WipsApp
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        try:
            app = WipsApp(root)
            root.update()
            self.assertTrue(app.demo.get())
            self.assertEqual(app.controller_port.get(), '23')
            self.assertEqual(app.ap_user.get(), 'root')
            self.assertEqual(app.ap_port.get(), '50022')
            self.assertTrue(app.auto_accept_ap_host_key.get())
            self.assertTrue(app.auto_recover.get())
            self.assertEqual(str(app.resume_button.cget('state')), 'disabled')
            for widget in app.secret_entries:
                self.assertTrue(widget.cget('show'))
            app._fill_demo()
            self.assertEqual(app.controller_ip.get(), '192.0.2.1')
            self.assertEqual(app.controller_port.get(), '23')
            self.assertEqual(app.ap_user.get(), 'root')
            cfg = app._snapshot('apply')
            self.assertEqual(cfg.controller_port, 23)
            self.assertEqual(cfg.ap_user, 'root')
            self.assertTrue(cfg.auto_accept_ap_host_key)
            self.assertIn('controller_return', app.table.cget('columns'))
            app._set_busy(True)
            self.assertEqual(str(app.controller_entry.cget('state')), 'disabled')
            self.assertEqual(str(app.verify_button.cget('state')), 'disabled')
            app._set_busy(False)
            self.assertEqual(str(app.verify_button.cget('state')), 'normal')
        finally:
            destroy_test_root(root)


class GuiConfirmationTests(unittest.TestCase):
    def test_change_confirmation_displays_ap_host_key_policy(self):
        from wec_wips.gui import WipsApp
        for automatic, expected in ((True, 'yes 자동 응답'), (False, '지문 확인 창')):
            with self.subTest(automatic=automatic):
                app = object.__new__(WipsApp)
                app.busy = False
                app.root = None
                app.syntax = SimpleNamespace(get=lambda: 'NAT 포함')
                app.nat_mode = SimpleNamespace(get=lambda: '기존 값 유지')
                cfg = SimpleNamespace(demo=False, controller_ip='192.0.2.1', controller_port=23, ap_port=50022,
                                      ap_ips=['192.0.2.10'], server_ip='198.51.100.20',
                                      auto_accept_ap_host_key=automatic)
                app._snapshot = lambda mode: cfg
                with patch('wec_wips.gui.messagebox.askyesno', return_value=False) as dialog:
                    app._start('apply')
                self.assertIn(expected, dialog.call_args.args[1])
                self.assertIn('컨트롤러 Telnet: 192.0.2.1:23', dialog.call_args.args[1])
                self.assertIn('AP SSH 포트: 50022', dialog.call_args.args[1])

    def test_details_show_controller_return_verification(self):
        from wec_wips.gui import WipsApp
        app = object.__new__(WipsApp)
        app.root = None
        app.table = SimpleNamespace(selection=lambda: ('0',))
        app.results = [SimpleNamespace(ap_ip='192.0.2.10', status='변경확인', simulated=False,
                                       before_ip='198.51.100.10', after_ip='198.51.100.20',
                                       before_nat='1', after_nat='1', key_check='일치',
                                       target_ip='198.51.100.20', ip_check='일치',
                                       controller_return='복귀확인', message='확인 완료')]
        with patch('wec_wips.gui.messagebox.showinfo') as dialog:
            app._result_details()
        self.assertIn('컨트롤러 복귀: 복귀확인', dialog.call_args.args[1])
        self.assertIn('목표 서버 IP: 198.51.100.20', dialog.call_args.args[1])
        self.assertIn('IP 확인: 일치', dialog.call_args.args[1])

    def test_completion_text_identifies_demo_and_real_results(self):
        from wec_wips.gui import WipsApp
        for simulated, expected in ((True, '모의 실행'), (False, '실제 장비')):
            with self.subTest(simulated=simulated):
                app = object.__new__(WipsApp)
                app.events = queue.Queue()
                app.events.put(('done', {'cancelled': False}))
                app.results = []
                app.run_simulated = simulated
                captured = []
                app.status = SimpleNamespace(set=captured.append)
                app.closing = False
                app.root = SimpleNamespace(after=lambda *_: None)
                app._pump()
                self.assertIn(expected, captured[-1])


class RecoveryGuiTests(unittest.TestCase):
    def make_app(self):
        from wec_wips.gui import WipsApp
        app = object.__new__(WipsApp)
        app.events = queue.Queue()
        app.stop_event = threading.Event()
        app.results = []
        app.closing = False
        app.busy = True
        app.worker = None
        app.run_simulated = False
        app.status_text = []
        app.status = SimpleNamespace(set=app.status_text.append)
        app.scheduled = []
        app.root = SimpleNamespace(after=lambda *args: app.scheduled.append(args))
        app._set_busy = lambda value: setattr(app, 'busy', value)
        app._log = lambda value: None
        app.phase_started = 10.0
        app.last_activity = 10.0
        app.phase = ''
        app.active_ap = ''
        app.active_attempt = 1
        app.retry_until = None
        app.local_record_failed = False
        app.ui_failed = False
        return app

    def test_render_failure_requests_stop_but_next_pump_consumes_worker_end(self):
        app = self.make_app()
        def broken_log(_):
            raise RuntimeError('SECRET must not be displayed')
        app._log = broken_log
        app.events.put(('log', {'message': 'safe message'}))
        app.events.put(('worker_end', {}))
        try:
            app._pump()
        except RuntimeError:
            pass
        self.assertTrue(app.stop_event.is_set(), 'render failure must stop the worker')
        self.assertEqual(len(app.scheduled), 1, 'pump must always reschedule')
        self.assertNotIn('SECRET', str(app.status_text))
        app._pump()
        self.assertFalse(app.busy)

    def test_phase_activity_and_retry_countdown_are_shown_and_finish_clears_them(self):
        app = self.make_app()
        app.events.put(('stage', {'ap_ip': '192.0.2.10', 'stage': '변경 후 조회', 'attempt': 2}))
        app.events.put(('activity', {'ap_ip': '192.0.2.10'}))
        with patch('wec_wips.gui.time.monotonic', return_value=20.0):
            app._pump()
        self.assertIn('변경 후 조회', app.status_text[-1])
        app.events.put(('retry', {'ap_ip': '192.0.2.10', 'attempt': 2, 'max_attempts': 3,
                                  'delay': 10.0, 'error_code': 'READ_TIMEOUT'}))
        with patch('wec_wips.gui.time.monotonic', return_value=20.0): app._pump()
        with patch('wec_wips.gui.time.monotonic', return_value=23.0): app._pump()
        self.assertIn('7초', app.status_text[-1])
        app.events.put(('worker_end', {}))
        with patch('wec_wips.gui.time.monotonic', return_value=30.0): app._pump()
        self.assertFalse(app.busy)
        self.assertNotIn('재시도 대기', app.status_text[-1])

    def test_resume_uses_original_snapshot_not_edited_form_and_preserves_prior_results(self):
        from wec_wips.core import RunConfig, Result
        app = self.make_app()
        app.busy = False
        app.saved_config = RunConfig('192.0.2.1', 23, 'root', 'ControllerSecret',
                                     ['192.0.2.10', '192.0.2.11'], 50022, 'root', 'APSecret',
                                     server_ip='198.51.100.1', shared_key='KeySecret')
        app.saved_mode = 'apply'
        app.results = [Result('now', '192.0.2.10', '변경확인'), Result('now', '192.0.2.11', '미실행')]
        app._snapshot = lambda _: self.fail('resume must not read edited fields')
        captures = []
        app._begin = lambda *args: captures.append(args)
        with patch('wec_wips.gui.messagebox.askyesno', return_value=True) as confirm:
            app._resume()
        self.assertEqual(len(captures), 1)
        cfg, mode, prior = captures[0]
        self.assertEqual(cfg.server_ip, '198.51.100.1')
        self.assertEqual(mode, 'apply')
        self.assertIsNot(cfg, app.saved_config)
        self.assertIsNot(prior[0], app.results[0])
        self.assertEqual([r.status for r in prior], ['변경확인', '미실행'])
        message = confirm.call_args.args[1]
        self.assertIn('198.51.100.1', message)
        self.assertIn('같은 목표', message)
        self.assertNotIn('KeySecret', message)

    def test_resume_includes_targets_missing_from_partial_worker_results(self):
        from wec_wips.core import RunConfig, Result
        app = self.make_app()
        app.busy = False
        app.saved_config = RunConfig('192.0.2.1', 23, 'root', 'Secret',
                                     ['192.0.2.10', '192.0.2.11'], 50022, 'root', 'Secret', demo=True)
        app.saved_mode = 'inspect'
        app.results = [Result('now', '192.0.2.10', '조회완료')]
        captures = []
        app._begin = lambda *args: captures.append(args)
        with patch('wec_wips.gui.messagebox.showinfo'):
            app._resume()
        self.assertEqual(len(captures), 1)
        self.assertEqual(captures[0][0].ap_ips, ['192.0.2.10', '192.0.2.11'])
        app._show_completion(False)
        self.assertIn('미실행 1', app.status_text[-1])
        app.results = []
        with patch('wec_wips.gui.messagebox.showinfo'):
            app._resume()
        self.assertEqual(len(captures), 2)

    def test_worker_exception_posts_inflight_snapshot_before_error_and_end(self):
        import sys
        from wec_wips.core import Result
        app = self.make_app()
        uncertain = Result('now', '192.0.2.11', '확인불가', config_sent=True, expected_nat='2')
        class Journal:
            directory = Path('/tmp/test-run')
            def __init__(self, *_): pass
            def record(self, *_): pass
            def close(self): pass
        class BrokenRunner:
            def __init__(self, *args, **kwargs): pass
            def run(self, mode): raise RuntimeError('KeySecret')
            def pending_results(self): return [uncertain]
        with patch.dict(sys.modules, {'wec_wips.journal': SimpleNamespace(LocalJournal=Journal)}), patch('wec_wips.core.Runner', BrokenRunner):
            app._run(SimpleNamespace(), 'apply')
        events = list(app.events.queue)
        kinds = [kind for kind, data in events]
        self.assertLess(kinds.index('worker_partial'), kinds.index('worker_error'))
        self.assertEqual(kinds[-1], 'worker_end')
        pending = next(data['results'] for kind, data in events if kind == 'worker_partial')
        self.assertTrue(pending[0].config_sent)
        self.assertEqual(pending[0].expected_nat, '2')
        self.assertNotIn('KeySecret', repr(events))

    def test_partial_worker_results_preserve_uncertain_write_without_duplicate_rows(self):
        from wec_wips.core import Result
        app = self.make_app()
        app.results = [Result('now', '192.0.2.10', '변경확인')]
        rows = []
        app.table = SimpleNamespace(get_children=lambda: tuple(str(i) for i in range(len(rows))),
            delete=lambda *args: rows.clear(), insert=lambda *args, **kwargs: rows.append(kwargs['values']), see=lambda *_: None)
        app.progress = SimpleNamespace(configure=lambda **kwargs: None)
        uncertain = Result('now', '192.0.2.11', '확인불가', config_sent=True, expected_nat='2')
        app.events.put(('worker_partial', {'results': [app.results[0], uncertain]}))
        app._pump()
        self.assertEqual([result.ap_ip for result in app.results], ['192.0.2.10', '192.0.2.11'])
        self.assertEqual(len(rows), 2)
        self.assertTrue(app.results[1].config_sent)
        self.assertEqual(app.results[1].expected_nat, '2')

    def test_partial_snapshot_survives_table_render_failure_before_uncertain_row(self):
        from wec_wips.core import Result
        app = self.make_app()
        completed = Result('now', '192.0.2.10', '변경확인')
        uncertain = Result('now', '192.0.2.11', '확인불가', config_sent=True, expected_nat='2')
        app.results = [completed]
        def failed_insert(*args, **kwargs): raise RuntimeError('render failure')
        app.table = SimpleNamespace(get_children=lambda: (), delete=lambda *args: None,
                                    insert=failed_insert, see=lambda *_: None)
        app.progress = SimpleNamespace(configure=lambda **kwargs: None)
        app.events.put(('worker_partial', {'results': [completed, uncertain]}))
        app._pump()
        self.assertEqual(len(app.results), 2)
        self.assertTrue(app.results[1].config_sent)
        self.assertEqual(app.results[1].expected_nat, '2')
        self.assertTrue(app.stop_event.is_set())
        self.assertEqual(len(app.scheduled), 1)

    def test_record_failure_after_done_remains_visible_without_stopping_job(self):
        app = self.make_app()
        app.events.put(('done', {'cancelled': False}))
        app.events.put(('local_record_error', {}))
        app.events.put(('worker_end', {}))
        app._pump()
        self.assertFalse(app.stop_event.is_set())
        self.assertFalse(app.busy)
        self.assertIn('기록', app.status_text[-1])
        self.assertIn('실패', app.status_text[-1])

    def test_journal_io_failures_still_forward_results_and_worker_end_without_secrets(self):
        import sys
        from wec_wips.core import Result
        cfg = SimpleNamespace(controller_password='ControllerSecret', shared_key='KeySecret')
        for failing in ('create', 'record', 'close'):
            with self.subTest(failing=failing):
                app = self.make_app()
                class Journal:
                    directory = Path('/tmp/test-run')
                    def __init__(self, *_):
                        if failing == 'create': raise OSError('KeySecret')
                    def record(self, *_):
                        if failing == 'record': raise OSError('KeySecret')
                    def close(self):
                        if failing == 'close': raise OSError('KeySecret')
                class FakeRunner:
                    def __init__(self, cfg, emit, confirm, stop, resume_results=None): self.emit = emit
                    def run(self, mode):
                        self.emit('result', {'result': Result('now', '192.0.2.10', '조회완료')})
                        self.emit('done', {'cancelled': False})
                with patch.dict(sys.modules, {'wec_wips.journal': SimpleNamespace(LocalJournal=Journal)}), patch('wec_wips.core.Runner', FakeRunner):
                    app._run(cfg, 'inspect')
                events = list(app.events.queue)
                kinds = [kind for kind, _ in events]
                self.assertIn('result', kinds)
                self.assertIn('done', kinds)
                self.assertIn('local_record_error', kinds)
                self.assertEqual(kinds[-1], 'worker_end')
                self.assertFalse(app.stop_event.is_set())
                self.assertNotIn('worker_error', kinds)
                self.assertNotIn('Secret', repr(events))

    def test_completion_counts_distinguish_unprocessed_from_success(self):
        from wec_wips.core import Result
        app = self.make_app()
        app.results = [Result('now', '192.0.2.10', '변경확인'),
                       Result('now', '192.0.2.11', '확인불가'),
                       Result('now', '192.0.2.12', '미실행')]
        app.events.put(('done', {'cancelled': False}))
        app._pump()
        self.assertIn('완료 1', app.status_text[-1])
        self.assertIn('확인필요 1', app.status_text[-1])
        self.assertIn('미실행 1', app.status_text[-1])


if __name__ == '__main__':
    unittest.main()


class ReportGuiTests(unittest.TestCase):
    def make_app(self):
        from wec_wips.gui import WipsApp
        from wec_wips.core import Result
        app = object.__new__(WipsApp)
        app.root = None
        app.busy = False
        app.exporting = False
        app.results = [Result('now', '192.0.2.10', 'IP일치'), Result('now', '192.0.2.11', 'IP불일치')]
        app.events = queue.Queue()
        app.stop_event = threading.Event()
        app.status_text = []
        app.status = SimpleNamespace(set=app.status_text.append)
        app._set_busy = lambda value: setattr(app, 'busy', value)
        app.phase = ''
        app.closing = False
        app._log = lambda value: None
        return app

    def test_report_actions_are_available(self):
        from wec_wips.gui import WipsApp
        self.assertTrue(hasattr(WipsApp, '_save_report'))
        self.assertTrue(hasattr(WipsApp, '_save_selected_txt'))

    def test_selected_txt_saves_only_selected_snapshot(self):
        app = self.make_app()
        app.table = SimpleNamespace(selection=lambda: ('1',))
        calls = []
        app._launch_export = lambda *args: calls.append(args)
        with patch('wec_wips.gui.filedialog.askdirectory', return_value='/tmp/export'):
            app._save_selected_txt()
        self.assertEqual(calls[0][0], 'txt')
        self.assertEqual([r.ap_ip for r in calls[0][2]], ['192.0.2.11'])

    def test_no_selection_does_not_choose_folder(self):
        app = self.make_app()
        app.table = SimpleNamespace(selection=lambda: ())
        with patch('wec_wips.gui.messagebox.showinfo') as info, patch('wec_wips.gui.filedialog.askdirectory') as folder:
            app._save_selected_txt()
        info.assert_called_once();folder.assert_not_called()

    def test_export_worker_only_receives_copy_of_results(self):
        app = self.make_app()
        captures = []
        class Thread:
            def __init__(self, target, args, **kw): captures.append((target, args))
            def start(self): pass
        with patch('wec_wips.gui.threading.Thread', Thread):
            app._launch_export('report', '/tmp/export', app.results)
        app.results[0].status = '미실행'
        snapshot = captures[0][1][2]
        self.assertEqual(snapshot[0].status, 'IP일치')
        self.assertTrue(app.busy)
        self.assertTrue(app.exporting)

    def test_worker_export_failure_has_no_exception_text(self):
        import sys
        app = self.make_app()
        def broken(*args, **kwargs): raise OSError('SECRET_INTERNAL_PATH')
        with patch.dict(sys.modules, {'wec_wips.reports':SimpleNamespace(write_report_bundle=broken, export_ap_txts=broken)}):
            app._run_export('report', '/tmp/export', app.results)
        events=list(app.events.queue)
        self.assertEqual([kind for kind, _ in events], ['export_error', 'export_end'])
        self.assertNotIn('SECRET', repr(events))

    def test_worker_report_success_returns_local_html_path(self):
        import sys
        app=self.make_app()
        with tempfile.TemporaryDirectory() as folder:
            out=Path(folder)/'run';out.mkdir();(out/'report.html').write_text('test')
            with patch.dict(sys.modules, {'wec_wips.reports':SimpleNamespace(write_report_bundle=lambda *args:out, export_ap_txts=lambda *args:out)}):
                app._run_export('report', folder, app.results)
            done=app.events.get_nowait()
            self.assertEqual(done[0],'export_done')
            self.assertEqual(done[1]['report_file'],str(out/'report.html'))
            self.assertEqual(done[1]['count'],2)

    def test_close_during_export_waits_without_stopping_device(self):
        app=self.make_app();app.exporting=True;app.busy=True
        app._stop=lambda:self.fail('export close must not call device stop')
        with patch('wec_wips.gui.messagebox.askyesno',return_value=True):
            app._close()
        self.assertTrue(app.closing)
        self.assertFalse(app.stop_event.is_set())

    def test_export_events_keep_success_path_and_release_busy_on_failure(self):
        app=self.make_app();app.busy=True;app.exporting=True
        app.root=SimpleNamespace(after=lambda *args:None)
        app.events.put(('export_done',{'path':'/tmp/export/run','report_file':'/tmp/export/run/report.html',
                                       'count':2,'label':'보고서 저장 완료'}))
        app.events.put(('export_end',{}))
        app._pump()
        self.assertFalse(app.busy);self.assertFalse(app.exporting)
        self.assertEqual(app.report_file,Path('/tmp/export/run/report.html'))
        self.assertIn('AP 2개',app.status_text[-1])
        app.busy=True;app.exporting=True
        app.events.put(('export_error',{}));app.events.put(('export_end',{}))
        app._pump()
        self.assertFalse(app.busy);self.assertFalse(app.exporting)
        self.assertEqual(len(app.results),2)
        self.assertIn('실패',app.status_text[-1])

    def test_report_open_uses_only_existing_local_html_file(self):
        app=self.make_app()
        with tempfile.TemporaryDirectory() as folder:
            app.report_file=Path(folder)/'report.html';app.report_file.write_text('test')
            with patch('wec_wips.gui.webbrowser.open',return_value=True) as browser:
                app._open_report()
            if __import__('os').name!='nt':
                self.assertEqual(browser.call_args.args[0],app.report_file.resolve().as_uri())
            app.report_file=Path(folder)/'missing.html'
            with patch('wec_wips.gui.messagebox.showerror') as error:
                app._open_report()
            error.assert_called_once()

    def test_actual_gui_exports_in_background_and_selected_txt_only(self):
        import sys
        import tkinter as tk
        from wec_wips.gui import WipsApp
        from wec_wips.core import Result
        try:
            root=tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        release=threading.Event();started=threading.Event();calls=[]
        try:
            app=WipsApp(root)
            rows=[Result('now','192.0.2.10','IP일치'),Result('now','192.0.2.11','IP불일치')]
            for row in rows:app._append_result(row)
            app._set_busy(False)
            self.assertEqual(str(app.table.cget('selectmode')),'extended')
            def report(folder, snapshot):
                calls.append(('report',threading.get_ident(),snapshot));started.set();release.wait(2)
                out=Path(folder)/'report-run';out.mkdir();(out/'report.html').write_text('test');return out
            def txt(folder,snapshot):
                calls.append(('txt',threading.get_ident(),snapshot))
                out=Path(folder)/'txt-run';out.mkdir();return out
            with tempfile.TemporaryDirectory() as folder, patch.dict(sys.modules,{'wec_wips.reports':SimpleNamespace(write_report_bundle=report,export_ap_txts=txt)}):
                with patch('wec_wips.gui.filedialog.askdirectory',return_value=folder):app.report_button.invoke()
                self.assertTrue(started.wait(1));root.update()
                self.assertTrue(app.busy);self.assertTrue(app.exporting)
                self.assertEqual(str(app.apply_button.cget('state')),'disabled')
                self.assertEqual(str(app.stop_button.cget('state')),'disabled')
                self.assertEqual(str(app.report_button.cget('state')),'disabled')
                self.assertNotEqual(calls[0][1],threading.get_ident())
                app.results[0].status='미실행'
                self.assertEqual(calls[0][2][0].status,'IP일치')
                release.set()
                deadline=time.monotonic()+3
                while app.busy and time.monotonic()<deadline:root.update();time.sleep(.01)
                self.assertFalse(app.busy)
                self.assertEqual(str(app.open_report_button.cget('state')),'normal')
                app.table.selection_set('1')
                with patch('wec_wips.gui.filedialog.askdirectory',return_value=folder):app.txt_button.invoke()
                deadline=time.monotonic()+3
                while app.busy and time.monotonic()<deadline:root.update();time.sleep(.01)
                self.assertEqual([r.ap_ip for r in calls[1][2]],['192.0.2.11'])
                self.assertFalse(app.busy)
        finally:
            release.set()
            if 'app' in locals() and app.worker is not None:app.worker.join(3)
            destroy_test_root(root)


class HostnameGuiTests(unittest.TestCase):
    def test_csv_hostname_parser_available(self):
        import wec_wips.gui as gui
        self.assertTrue(hasattr(gui,'csv_ap_entries'))

    def test_csv_optional_hostname_and_credentials_are_separate(self):
        from wec_wips.gui import csv_ap_entries, csv_ip_text
        source='ap_ip,hostname,id,password\n192.0.2.10,서울 AP-01,root,SECRET\n192.0.2.11,AP02,root,SECRET2\n'
        ips,names=csv_ap_entries(source)
        self.assertEqual(ips,['192.0.2.10','192.0.2.11'])
        self.assertEqual(names,{'192.0.2.10':'서울 AP-01','192.0.2.11':'AP02'})
        self.assertNotIn('SECRET',repr(names))
        self.assertEqual(csv_ip_text(source),'192.0.2.10\n192.0.2.11')

    def test_explicit_hostname_headers_only_and_conflicts_rejected(self):
        from wec_wips.gui import csv_ap_entries
        for column in ('hostname','ap_hostname','AP Name','호스트명'):
            with self.subTest(column=column):
                self.assertEqual(csv_ap_entries(f'ap_ip,{column}\n192.0.2.10,AP-01\n')[1],{'192.0.2.10':'AP-01'})
        self.assertEqual(csv_ap_entries('ap_ip,name\n192.0.2.10,SECRET\n')[1],{})
        for source in ('ap_ip,hostname,AP Name\n192.0.2.10,AP1,AP1\n',
                       'ap_ip,hostname\n192.0.2.10,AP1\n192.0.2.10,AP2\n',
                       'ap_ip,hostname\n192.0.2.10,<SECRET>\n'):
            with self.assertRaises(ValueError) as caught:csv_ap_entries(source)
            self.assertNotIn('SECRET',str(caught.exception))

    def test_actual_gui_hostname_default_and_filtered_csv_map(self):
        import tkinter as tk
        from wec_wips.gui import WipsApp
        from wec_wips.core import Result
        try:root=tk.Tk()
        except tk.TclError as exc:self.skipTest(f'No display: {exc}')
        try:
            app=WipsApp(root);app._fill_demo()
            self.assertTrue(app.lookup_hostnames.get())
            self.assertIn('hostname',app.table.cget('columns'))
            app.ap_hostnames={'192.0.2.101':'AP101','192.0.2.102':'AP102'}
            app.ap_text.delete('1.0','end');app.ap_text.insert('1.0','192.0.2.101\n192.0.2.103')
            cfg=app._snapshot('verify_ip')
            self.assertEqual(cfg.ap_hostnames,{'192.0.2.101':'AP101'})
            self.assertTrue(cfg.lookup_hostnames)
            r=Result('now','192.0.2.101','IP일치',hostname='AP101',hostname_source='csv')
            app._append_result(r)
            self.assertEqual(app.table.set('0','hostname'),'AP101')
            app.table.selection_set('0')
            with patch('wec_wips.gui.messagebox.showinfo') as info:app._result_details()
            self.assertIn('AP101',info.call_args.args[1])
            self.assertIn('csv',info.call_args.args[1])
        finally:destroy_test_root(root)
