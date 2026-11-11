import csv
import io
import tempfile
import threading
import unittest
from dataclasses import asdict
from pathlib import Path

from wec_wips import core


def config(**kw):
    args = dict(controller_ip='192.0.2.1', controller_port=23,
                controller_user='operator', controller_password='ControlSecret',
                ap_ips=['192.0.2.10'], ap_port=50022, ap_user='apadmin',
                ap_password='APSecret', server_ip='198.51.100.10', shared_key='NewSecret')
    args.update(kw)
    return core.RunConfig(**args)


def summary(ip='192.0.2.100', nat='2', key='OldSecret'):
    return (f'ap01# show config wips summary\r\n'
            f'wips mode ........ WIPS_SENSOR_MODE\r\n'
            f'wips server ip ........ {ip}\r\n'
            f'wips nat ........ {nat}\r\n'
            f'wips sharedkey ........ {key}\r\n'
            'ap01#')


class ScriptedSession:
    responses = []
    commands = []
    closed = 0
    instances = 0
    flow = []
    fail_exit = False
    def __init__(self, cfg, stop, confirm):
        self.stop = stop
        self.controller_ready = False
        type(self).instances += 1
    def connect(self, ap_ip):
        self.controller_ready = False
        self.flow.append(('ssh', ap_ip))
    def execute(self, command):
        self.commands.append(command)
        item = self.responses.pop(0)
        if isinstance(item, Exception): raise item
        if callable(item): return item(self)
        return item
    def leave_ap(self):
        self.flow.append(('exit',))
        if self.fail_exit: raise RuntimeError('OldSecret secret in uncertain exit')
        self.controller_ready = True
    def close(self):
        self.controller_ready = False
        type(self).closed += 1


class CoreTests(unittest.TestCase):
    def setUp(self):
        ScriptedSession.responses = []
        ScriptedSession.commands = []
        ScriptedSession.closed = 0
        ScriptedSession.instances = 0
        ScriptedSession.flow = []
        ScriptedSession.fail_exit = False
        self.events = []
        self.stop = threading.Event()

    def run_job(self, responses, mode='apply', **kw):
        ScriptedSession.responses = responses[:]
        runner = core.Runner(config(**kw), lambda k, d: self.events.append((k, d)),
                             lambda *a: False, self.stop, ScriptedSession)
        return runner.run(mode)

    def test_parser_exact_fields_not_echo(self):
        value = core.parse_summary('config wips server 203.0.113.1 1 xxx\n' + summary())
        self.assertEqual(value.server_ip, '192.0.2.100')
        self.assertEqual(value.nat, '2')
        self.assertEqual(value.shared_key, 'OldSecret')
        self.assertNotIn('OldSecret', repr(value))

    def test_parser_rejects_missing_duplicate_invalid_server(self):
        for text in ['AP# config wips server 198.51.100.10 1 key',
                     summary() + '\nwips server ip ...... 192.0.2.2',
                     summary(ip='192.0.2.100 extra'), summary(ip='999.1.1.1')]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                core.parse_summary(text)

    def test_input_dedup_and_injection(self):
        self.assertEqual(core.parse_ap_ips('192.0.2.10, 192.0.2.11\n192.0.2.10'),
                         ['192.0.2.10','192.0.2.11'])
        for value in ['192.0.2.10;reboot','192.0.2.0/24','0.0.0.0','224.0.0.1']:
            with self.assertRaises(ValueError): core.parse_ap_ips(value)
        for field, value in [('shared_key','abc\nreboot'), ('ap_user','a;reboot'),
                             ('ap_password','abc\n'), ('ap_port',0)]:
            with self.assertRaises(ValueError): config(**{field:value}).validate('apply')

    def test_inspect_never_sends_change_and_needs_no_key(self):
        results = self.run_job([summary()], mode='inspect', server_ip='', shared_key='')
        self.assertEqual(ScriptedSession.commands, ['show config wips summary'])
        self.assertEqual(results[0].status, '조회완료')

    def test_apply_preserves_nat_then_verifies_key_and_ip(self):
        results = self.run_job([summary(), '', summary('198.51.100.10','2','NewSecret')])
        self.assertEqual(ScriptedSession.commands[1], 'config wips server 198.51.100.10 2 NewSecret')
        self.assertEqual(results[0].status, '변경확인')
        self.assertEqual(results[0].key_check, '일치')
        self.assertEqual(ScriptedSession.closed, 1)
        self.assertNotIn('OldSecret', repr(self.events))
        self.assertNotIn('NewSecret', repr(self.events))

    def test_missing_nat_refuses_mutation_in_preserve_mode(self):
        results = self.run_job([summary().replace('wips nat ........ 2\r\n','')])
        self.assertEqual(results[0].status, '실패')
        self.assertEqual(len(ScriptedSession.commands), 1)

    def test_unparseable_summary_refuses_mutation(self):
        results = self.run_job(['WEC8500#'])
        self.assertEqual(results[0].status, '실패')
        self.assertEqual(len(ScriptedSession.commands), 1)

    def test_masked_key_is_not_reported_verified(self):
        results = self.run_job([summary(), '', summary('198.51.100.10','2','********')])
        self.assertEqual(results[0].status, '부분확인')
        self.assertEqual(results[0].key_check, '확인불가')

    def test_already_equal_does_not_write(self):
        results = self.run_job([summary('198.51.100.10','2','NewSecret')])
        self.assertEqual(results[0].status, '이미일치')
        self.assertEqual(len(ScriptedSession.commands), 1)

    def test_mismatch_detected_and_later_ap_skipped(self):
        results = self.run_job([summary(), '', summary()], ap_ips=['192.0.2.10','192.0.2.11'])
        self.assertEqual([r.status for r in results], ['검증불일치','미실행'])

    def test_ambiguous_write_failure_not_retried(self):
        results = self.run_job([summary(), TimeoutError('OldSecret NewSecret APSecret ControlSecret')])
        self.assertEqual(results[0].status, '확인불가')
        self.assertEqual(len(ScriptedSession.commands), 2)
        for secret in ('OldSecret','NewSecret','APSecret','ControlSecret'):
            self.assertNotIn(secret, repr(self.events))

    def test_stop_after_write_reports_unknown(self):
        def stop_after_write(session):
            session.stop.set()
            return ''
        results = self.run_job([summary(), stop_after_write])
        self.assertEqual(results[0].status, '확인불가')
        self.assertEqual(len(ScriptedSession.commands), 2)

    def test_stop_before_write_does_not_change(self):
        def stop_after_read(session):
            session.stop.set()
            return summary()
        results = self.run_job([stop_after_read])
        self.assertEqual(results[0].status, '중지')
        self.assertEqual(len(ScriptedSession.commands), 1)

    def test_two_argument_syntax_is_explicit(self):
        results = self.run_job([summary(), '', summary('198.51.100.10','2','NewSecret')],
                               syntax='without_nat')
        self.assertEqual(ScriptedSession.commands[1], 'config wips server 198.51.100.10 NewSecret')
        self.assertEqual(results[0].status, '변경확인')

    def test_already_equal_without_nat_reports_partial_and_stops(self):
        text = summary('198.51.100.10','2','NewSecret').replace('wips nat ........ 2\r\n','')
        results = self.run_job([text], syntax='without_nat', ap_ips=['192.0.2.10','192.0.2.11'])
        self.assertEqual([r.status for r in results], ['부분확인','미실행'])
        self.assertEqual(len(ScriptedSession.commands), 1)

    def test_username_first_character_validated_before_connect(self):
        for name in ('-operator','.operator','@operator'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                config(ap_user=name).validate('inspect')

    def test_known_safe_transport_error_reaches_result(self):
        from wec_wips.transport import TransportError
        results = self.run_job([TransportError('AP SSH 인증에 실패했습니다. 자동 재시도하지 않습니다.')])
        self.assertIn('인증에 실패', results[0].message)

    def test_cli_error_never_succeeds(self):
        results = self.run_job([summary(), '% Invalid command: NewSecret'])
        self.assertEqual(results[0].status, '실패')
        self.assertNotIn('NewSecret', repr(self.events))

    def test_operator_csv_contains_returned_keys_but_no_login_credentials(self):
        results = self.run_job([summary(), '', summary('198.51.100.10','2','NewSecret')])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'result.csv'
            core.export_results(path, results)
            data = path.read_text(encoding='utf-8-sig')
            for secret in ('APSecret','ControlSecret'):
                self.assertNotIn(secret, data)
            for key in ('OldSecret', 'NewSecret'):
                self.assertIn(key, data)
                self.assertNotIn(key, repr(self.events))
            self.assertEqual(len(list(csv.DictReader(io.StringIO(data)))), 1)

    def test_demo_never_imports_or_uses_ssh(self):
        runner = core.Runner(config(demo=True), lambda *a: None, lambda *a: False, self.stop)
        result = runner.run('apply')[0]
        self.assertTrue(result.simulated)
        self.assertEqual(result.status, '변경확인')

    def test_controller_connection_reused_only_after_exit(self):
        results = self.run_job([summary(), '', summary('198.51.100.10','2','NewSecret'),
                                summary(), '', summary('198.51.100.10','2','NewSecret')],
                               ap_ips=['192.0.2.10','192.0.2.11'])
        self.assertEqual([r.status for r in results], ['변경확인','변경확인'])
        self.assertEqual(ScriptedSession.instances, 1)
        self.assertEqual(ScriptedSession.closed, 1)
        self.assertEqual(ScriptedSession.flow, [('ssh','192.0.2.10'),('exit',),('ssh','192.0.2.11'),('exit',)])
        self.assertEqual([r.controller_return for r in results], ['복귀확인','복귀확인'])

    def test_exit_failure_halts_batch_even_if_continue_on_error(self):
        ScriptedSession.fail_exit = True
        results = self.run_job([summary(), '', summary('198.51.100.10','2','NewSecret')],
                               ap_ips=['192.0.2.10','192.0.2.11'], stop_on_error=False)
        self.assertEqual([r.status for r in results], ['복귀실패','미실행'])
        self.assertEqual(results[0].after_ip, '198.51.100.10')
        self.assertEqual(results[0].controller_return, '미확인')
        self.assertEqual(ScriptedSession.flow, [('ssh','192.0.2.10'),('exit',)])
        self.assertNotIn('OldSecret', repr(self.events))

    def test_inspect_also_exits_before_next_ap(self):
        results = self.run_job([summary(), summary()], mode='inspect',
                               ap_ips=['192.0.2.10','192.0.2.11'])
        self.assertEqual([r.controller_return for r in results], ['복귀확인','복귀확인'])
        self.assertEqual(ScriptedSession.flow, [('ssh','192.0.2.10'),('exit',),('ssh','192.0.2.11'),('exit',)])

    def test_bad_summary_exits_and_may_continue_if_configured(self):
        results = self.run_job(['unrecognized summary', summary()], mode='inspect',
                               ap_ips=['192.0.2.10','192.0.2.11'], stop_on_error=False)
        self.assertEqual([r.status for r in results], ['실패','조회완료'])
        self.assertEqual([r.controller_return for r in results], ['복귀확인','복귀확인'])
        self.assertEqual(ScriptedSession.instances, 1)

    def test_verify_ip_requires_target_but_ignores_key_nat_and_mutation_syntax(self):
        for value in ('', 'not-an-ip', '999.1.1.1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                config(server_ip=value).validate('verify_ip')
        config(shared_key='', syntax='not-used', nat_mode='not-used').validate('verify_ip')
        config(shared_key='unsupported $ secret', syntax='without_nat', nat_mode='2').validate('verify_ip')

    def test_verify_ip_match_sends_only_summary_once_and_exits(self):
        results = self.run_job([summary('198.51.100.10', nat='disabled', key='********')],
                               mode='verify_ip', shared_key='', syntax='not-used', nat_mode='not-used')
        result = results[0]
        self.assertEqual(ScriptedSession.commands, [core.SUMMARY_COMMAND])
        self.assertEqual(ScriptedSession.flow, [('ssh','192.0.2.10'),('exit',)])
        self.assertEqual((result.status, result.target_ip, result.after_ip, result.ip_check),
                         ('IP일치', '198.51.100.10', '198.51.100.10', '일치'))
        self.assertEqual(result.before_ip, result.after_ip)
        self.assertEqual(result.key_check, '검사안함')
        self.assertIn('설정 변경 없이 조회', result.message)

    def test_verify_ip_mismatch_continues_all_aps_even_stop_on_error(self):
        results = self.run_job([summary(), summary('198.51.100.10')], mode='verify_ip',
                               ap_ips=['192.0.2.10','192.0.2.11'], stop_on_error=True)
        self.assertEqual([r.status for r in results], ['IP불일치','IP일치'])
        self.assertEqual([r.ip_check for r in results], ['불일치','일치'])
        self.assertEqual(ScriptedSession.commands, [core.SUMMARY_COMMAND]*2)
        self.assertEqual([r.controller_return for r in results], ['복귀확인','복귀확인'])

    def test_verify_ip_ignores_missing_duplicate_or_unrecognized_other_fields(self):
        for extra in ('', '\nwips nat ... invalid\nwips nat ... 999',
                      '\nwips sharedkey ... OldSecret\nwips sharedkey ... another-secret',
                      '\nwips mode ... UnexpectedMode\nwips sharedkey ... <hidden>'):
            with self.subTest(extra=extra):
                results = self.run_job(['wips server ip : 198.51.100.10'+extra], mode='verify_ip', shared_key='')
                self.assertEqual(results[0].status, 'IP일치')
                self.assertEqual(results[0].key_check, '검사안함')
                self.assertEqual(results[0].before_nat, '')
                self.assertEqual(results[0].after_nat, '')
                self.assertNotIn('OldSecret', repr(self.events))
                self.assertNotIn('another-secret', repr(self.events))

    def test_verify_ip_rejects_missing_duplicate_invalid_or_echo_server_fields(self):
        for text in ('config wips server 198.51.100.10 1 Key', 'show config wips summary',
                     'wips server ip ..... 198.51.100.10 extra',
                     'wips server ip ..... 999.1.1.1',
                     'wips server ip ..... 198.51.100.10\nwips server ip ..... 198.51.100.10',
                     'ap01# wips server ip ..... 198.51.100.10'):
            with self.subTest(text=text):
                results = self.run_job([text], mode='verify_ip',
                                       ap_ips=['192.0.2.10','192.0.2.11'])
                self.assertEqual([r.status for r in results], ['실패','미실행'])
                self.assertEqual(results[0].ip_check, '')
                self.assertEqual(results[0].after_ip, '')
                self.assertEqual(results[1].target_ip, '198.51.100.10')

    def test_verify_ip_exit_failure_preserves_comparison_and_stops(self):
        ScriptedSession.fail_exit = True
        results = self.run_job([summary()], mode='verify_ip',
                               ap_ips=['192.0.2.10','192.0.2.11'], stop_on_error=False)
        self.assertEqual([r.status for r in results], ['복귀실패','미실행'])
        self.assertEqual(results[0].ip_check, '불일치')
        self.assertEqual(results[0].after_ip, '192.0.2.100')
        self.assertEqual(results[0].target_ip, '198.51.100.10')
        self.assertEqual(results[0].controller_return, '미확인')

    def test_verify_ip_cancel_after_read_preserves_comparison_and_blocks_next(self):
        def cancel_after_read(session):
            session.stop.set()
            return summary('198.51.100.10')
        results = self.run_job([cancel_after_read], mode='verify_ip',
                               ap_ips=['192.0.2.10','192.0.2.11'])
        self.assertEqual([r.status for r in results], ['중지','미실행'])
        self.assertEqual(results[0].ip_check, '일치')
        self.assertEqual(results[0].after_ip, '198.51.100.10')
        self.assertEqual(results[0].target_ip, '198.51.100.10')
        self.assertEqual(ScriptedSession.commands, [core.SUMMARY_COMMAND])

    def test_verify_ip_demo_export_has_comparison_returned_key_but_no_login_secrets(self):
        runner = core.Runner(config(demo=True, shared_key='', server_ip='192.0.2.200'),
                             lambda *a: None, lambda *a: False, self.stop)
        results = runner.run('verify_ip')
        self.assertTrue(results[0].simulated)
        self.assertEqual(results[0].status, 'IP일치')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'verify.csv'
            core.export_results(path, results)
            data = path.read_text(encoding='utf-8-sig')
            row = next(csv.DictReader(io.StringIO(data)))
            self.assertEqual(row['target_ip'], '192.0.2.200')
            self.assertEqual(row['ip_check'], '일치')
            self.assertIn('wips sharedkey : DemoOldKey', row['summary_before'])
            for secret in ('APSecret','ControlSecret'):
                self.assertNotIn(secret, data)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.stop = threading.Event()
        self.sessions = []
        self.calls = []

    @staticmethod
    def transient(code='COMMAND_TIMEOUT'):
        from wec_wips.transport import TransportError
        return TransportError('안전한 통신 오류', code=code, retryable=True)

    def run_script(self, scripts, mode='apply', resume=None, emit=None, **kwargs):
        owner = self
        cfg = config(**kwargs)
        # Attaching defaults also lets these regression tests exercise v1.3.
        if not hasattr(cfg, 'auto_recover'): cfg.auto_recover = True
        if not hasattr(cfg, 'max_retries'): cfg.max_retries = 2
        cfg.retry_delays = (0.0, 0.0)
        specs = list(scripts)
        class Peer:
            def __init__(self, cfg, stop, confirm):
                self.spec = specs.pop(0)
                self.replies = list(self.spec.get('replies', []))
                self.controller_ready = False
                self.observer = lambda *a: None
                self.closed = False
                self.number = len(owner.sessions) + 1
                owner.sessions.append(self)
            def set_observer(self, observer): self.observer = observer
            def connect(self, ap):
                self.controller_ready = False
                owner.calls.append((self.number, 'connect', ap))
                self.observer('stage', {'stage': 'AP 로그인'})
                self.observer('activity', {})
                if self.spec.get('connect_error'): raise self.spec['connect_error']
            def execute(self, command):
                owner.calls.append((self.number, 'execute', command))
                reply = self.replies.pop(0)
                if isinstance(reply, Exception):
                    self.controller_ready = False
                    raise reply
                return reply
            def leave_ap(self):
                owner.calls.append((self.number, 'exit', ''))
                if self.spec.get('exit_error'): raise self.spec['exit_error']
                self.controller_ready = True
            def close(self):
                owner.calls.append((self.number, 'close', ''))
                self.closed, self.controller_ready = True, False
        def capture(kind, data):
            self.events.append((kind, data))
            if emit: emit(kind, data)
        args = {} if resume is None else {'resume_results': resume}
        self.last_runner = core.Runner(cfg, capture, lambda *a: False, self.stop, Peer, **args)
        return self.last_runner.run(mode)

    def writes(self):
        return [v for _, kind, v in self.calls if kind == 'execute' and v.startswith('config ')]

    def test_transient_read_reconnects_same_ap_and_continues(self):
        results = self.run_script([
            {'replies': [self.transient()]},
            {'replies': [summary(), summary()]},
        ], mode='inspect', ap_ips=['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in results], ['조회완료', '조회완료'])
        self.assertEqual([v for _, k, v in self.calls if k == 'connect'],
                         ['192.0.2.10', '192.0.2.10', '192.0.2.11'])
        self.assertEqual(len(self.sessions), 2)
        self.assertTrue(self.sessions[0].closed)
        self.assertEqual(results[0].attempts, 2)
        self.assertEqual(self.writes(), [])

    def test_ambiguous_write_requeries_then_skips_already_applied(self):
        result = self.run_script([
            {'replies': [summary(), self.transient('CONNECTION_CLOSED')]},
            {'replies': [summary('198.51.100.10', '2', 'NewSecret')]},
        ])[0]
        self.assertEqual(result.status, '이미일치')
        self.assertEqual(len(self.writes()), 1)
        self.assertTrue(result.config_sent)
        self.assertEqual(result.expected_nat, '2')
        self.assertEqual(result.before_ip, '192.0.2.100')
        self.assertEqual(result.after_ip, '198.51.100.10')

    def test_ambiguous_write_masked_key_never_replays_config(self):
        result = self.run_script([
            {'replies': [summary(), self.transient()]},
            {'replies': [summary('198.51.100.10', '2', '********')]},
        ])[0]
        self.assertEqual(result.status, '부분확인')
        self.assertEqual(result.error_code, 'RECOVERY_UNVERIFIABLE')
        self.assertEqual(len(self.writes()), 1)

    def test_recovery_preserves_original_nat_goal_before_reapplying(self):
        result = self.run_script([
            {'replies': [summary(nat='1'), self.transient()]},
            {'replies': [summary(nat='2'), '', summary('198.51.100.10', '1', 'NewSecret')]},
        ])[0]
        self.assertEqual(result.status, '변경확인')
        self.assertEqual(result.expected_nat, '1')
        self.assertEqual(self.writes(), ['config wips server 198.51.100.10 1 NewSecret'] * 2)

    def test_exit_timeout_recovers_and_reads_without_duplicate_write(self):
        result = self.run_script([
            {'replies': [summary(), '', summary('198.51.100.10', '2', 'NewSecret')],
             'exit_error': self.transient('RETURN_TIMEOUT')},
            {'replies': [summary('198.51.100.10', '2', 'NewSecret')]},
        ])[0]
        self.assertEqual(result.status, '이미일치')
        self.assertEqual(result.controller_return, '복귀확인')
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(result.attempts, 2)

    def test_retry_limit_is_three_attempts_then_remaining_skipped(self):
        results = self.run_script([{'connect_error': self.transient('AP_LOGIN_TIMEOUT')} for _ in range(3)],
                                  mode='inspect', ap_ips=['192.0.2.10', '192.0.2.11'])
        self.assertEqual(len(self.sessions), 3)
        self.assertEqual([r.status for r in results], ['실패', '미실행'])
        self.assertEqual(results[0].attempts, 3)
        self.assertEqual(results[0].error_code, 'AP_LOGIN_TIMEOUT')
        self.assertEqual(len([x for x in self.events if x[0] == 'retry']), 2)

    def test_auth_error_is_never_retried(self):
        from wec_wips.transport import TransportError
        result = self.run_script([{'connect_error': TransportError('AP 인증 실패')}], mode='inspect')[0]
        self.assertEqual(result.status, '실패')
        self.assertEqual(len(self.sessions), 1)
        self.assertFalse(any(k == 'retry' for k, _ in self.events))

    def test_stop_during_retry_countdown_prevents_new_connection(self):
        def emit(kind, data):
            if kind == 'retry': self.stop.set()
        result = self.run_script([{'connect_error': self.transient()}], mode='inspect', emit=emit)[0]
        self.assertTrue(self.stop.is_set())
        self.assertEqual(len(self.sessions), 1)
        self.assertEqual(result.status, '중지')

    def test_recovery_can_be_disabled(self):
        result = self.run_script([{'connect_error': self.transient()}], mode='inspect', auto_recover=False)[0]
        self.assertEqual(len(self.sessions), 1)
        self.assertEqual(result.status, '실패')
        self.assertFalse(any(k == 'retry' for k, _ in self.events))

    def test_resume_retains_completed_ap_and_only_processes_pending(self):
        previous = core.Result('earlier', '192.0.2.10', '조회완료', mode='inspect', controller_return='복귀확인')
        result = self.run_script([{'replies': [summary()]}], mode='inspect', resume=[previous],
                                 ap_ips=['192.0.2.10', '192.0.2.11'])
        self.assertEqual([v for _, k, v in self.calls if k == 'connect'], ['192.0.2.11'])
        self.assertEqual(result[0], previous)
        self.assertIsNot(result[0], previous)
        self.assertEqual([r.status for r in result], ['조회완료', '조회완료'])

    def test_resume_ambiguous_mutation_keeps_guard_against_masked_key(self):
        previous = core.Result('earlier', '192.0.2.10', '확인불가', mode='apply')
        previous.config_sent, previous.expected_nat = True, '2'
        result = self.run_script([{'replies': [summary('198.51.100.10', '2', '********')]}], resume=[previous])[0]
        self.assertEqual(result.status, '부분확인')
        self.assertEqual(self.writes(), [])

    def test_parse_error_with_exit_timeout_does_not_trigger_retry(self):
        result = self.run_script([{'replies': ['unparseable'], 'exit_error': self.transient('RETURN_TIMEOUT')}], mode='inspect')[0]
        self.assertEqual(result.status, '실패')
        self.assertEqual(len(self.sessions), 1)
        self.assertEqual(result.error_code, 'SUMMARY_INVALID')

    def test_cli_rejection_with_exit_timeout_does_not_trigger_retry(self):
        result = self.run_script([{'replies': [summary(), '% Invalid command: NewSecret'],
                                  'exit_error': self.transient('RETURN_TIMEOUT')}])[0]
        self.assertEqual(result.status, '실패')
        self.assertEqual(result.error_code, 'CLI_REJECTED')
        self.assertEqual(len(self.sessions), 1)

    def test_recovery_repr_excludes_keys_and_operator_csv_retains_returned_keys(self):
        result = self.run_script([
            {'replies': [summary(), self.transient()]},
            {'replies': [summary('198.51.100.10', '2', 'NewSecret')]},
        ])[0]
        self.assertTrue(any(k == 'stage' for k, _ in self.events))
        self.assertTrue(any(k == 'activity' for k, _ in self.events))
        self.assertTrue(any(k == 'retry' for k, _ in self.events))
        self.assertGreaterEqual(result.duration_seconds, 0)
        self.assertEqual(result.error_code, '')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'result.csv'
            core.export_results(path, [result])
            text = path.read_text(encoding='utf-8-sig')
        for secret in ('OldSecret', 'NewSecret', 'APSecret', 'ControlSecret'):
            self.assertNotIn(secret, repr(self.events))
        for password in ('APSecret', 'ControlSecret'):
            self.assertNotIn(password, text)
        for key in ('OldSecret', 'NewSecret'):
            self.assertIn(key, text)

    def test_invalid_recovery_options_rejected_before_work(self):
        cfg = config()
        self.assertTrue(hasattr(cfg, 'max_retries'), 'Recovery configuration is missing')
        for name, value in [('max_retries', 3), ('max_retries', -1), ('max_retries', True),
                            ('retry_delays', (float('nan'), 0)), ('retry_delays', (-1, 0)),
                            ('retry_delays', (31, 0)), ('retry_delays', (0,)), ('auto_recover', 'yes')]:
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                cfg = config(); setattr(cfg, name, value); cfg.validate('inspect')

    def test_event_delivery_failure_propagates_without_false_success(self):
        def emit(kind, data):
            if kind == 'stage': raise RuntimeError('event sink unavailable')
        with self.assertRaises(Exception):
            self.run_script([{'replies': [summary()]}], mode='inspect', emit=emit)
        self.assertFalse(any(k == 'result' and d['result'].status == '조회완료' for k, d in self.events))


    def test_failed_event_delivery_sets_stop_before_transport_can_write(self):
        def emit(kind, data):
            if kind == 'stage': raise RuntimeError('event sink unavailable')
        with self.assertRaises(Exception):
            self.run_script([{'replies': [summary()]}], emit=emit)
        self.assertTrue(self.stop.is_set())
        self.assertEqual(self.writes(), [])

    def test_failed_event_after_write_preserves_resume_guard(self):
        def emit(kind, data):
            if kind == 'stage' and data.get('stage') == '변경 후 조회':
                raise RuntimeError('event sink unavailable')
        with self.assertRaises(Exception):
            self.run_script([{'replies': [summary(), '']}], emit=emit)
        self.assertEqual(len(self.writes()), 1)
        pending = self.last_runner.pending_results()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].status, '확인불가')
        self.assertTrue(pending[0].config_sent)
        self.assertEqual(pending[0].expected_nat, '2')
        self.assertEqual(pending[0].error_code, 'INTERNAL_ERROR')
        pending[0].message = 'changed copy'
        self.assertNotEqual(self.last_runner.pending_results()[0].message, 'changed copy')
        self.stop.clear(); self.calls.clear()
        result = self.run_script([{'replies': [summary('198.51.100.10', '2', '********')]}], resume=pending)[0]
        self.assertEqual(self.writes(), [])
        self.assertEqual(result.status, '부분확인')

    def test_pending_results_include_completed_and_failed_current_ap(self):
        def emit(kind, data):
            if kind == 'stage' and data.get('ap_ip') == '192.0.2.11':
                raise RuntimeError('event sink unavailable')
        with self.assertRaises(Exception):
            self.run_script([{'replies': [summary()]}], mode='inspect', emit=emit,
                            ap_ips=['192.0.2.10', '192.0.2.11'])
        pending = self.last_runner.pending_results()
        self.assertEqual([r.ap_ip for r in pending], ['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in pending], ['조회완료', '실패'])

    def test_inspect_recovery_returns_fresh_value_after_exit_failure(self):
        result = self.run_script([
            {'replies': [summary()], 'exit_error': self.transient('RETURN_TIMEOUT')},
            {'replies': [summary('192.0.2.250', '1')]},
        ], mode='inspect')[0]
        self.assertEqual(result.status, '조회완료')
        self.assertEqual(result.before_ip, '192.0.2.250')
        self.assertEqual(result.before_nat, '1')


    def test_pending_results_retain_unvisited_prior_write_on_early_worker_error(self):
        first = core.Result('earlier', '192.0.2.10', '조회완료', mode='apply', controller_return='복귀확인')
        second = core.Result('earlier', '192.0.2.11', '확인불가', mode='apply',
                             config_sent=True, expected_nat='2')
        def fail_before_ap(kind, data):
            if kind == 'progress': raise RuntimeError('event sink unavailable')
        with self.assertRaises(Exception):
            self.run_script([], resume=[first, second], emit=fail_before_ap,
                            ap_ips=['192.0.2.10', '192.0.2.11'])
        pending = self.last_runner.pending_results()
        self.assertEqual([r.ap_ip for r in pending], ['192.0.2.10', '192.0.2.11'])
        self.assertTrue(pending[1].config_sent)
        self.assertEqual(pending[1].expected_nat, '2')
        self.stop.clear(); self.calls.clear()
        results = self.run_script([{'replies': [summary('198.51.100.10', '2', '********')]}],
                                  resume=pending, ap_ips=['192.0.2.10', '192.0.2.11'])
        self.assertEqual(results[1].status, '부분확인')
        self.assertEqual(self.writes(), [])

    def test_report_recovery_keeps_original_before_and_latest_after(self):
        result = self.run_script([
            {'replies': [summary(), self.transient('CONNECTION_CLOSED')]},
            {'replies': [summary('198.51.100.10', '2', '********')]},
        ])[0]
        self.assertEqual(result.status, '부분확인')
        self.assertIn('192.0.2.100', result.summary_before)
        self.assertIn('198.51.100.10', result.summary_after)
        self.assertEqual(result.ip_check, '일치')
        self.assertEqual(len(self.writes()), 1)
        self.assertIn('wips sharedkey : OldSecret', result.summary_before)
        self.assertIn('wips sharedkey : ********', result.summary_after)

    def test_inspect_recovery_refreshes_summary_and_has_no_target_comparison(self):
        result = self.run_script([
            {'replies': [summary()], 'exit_error': self.transient('RETURN_TIMEOUT')},
            {'replies': [summary('192.0.2.250', '1')]},
        ], mode='inspect')[0]
        self.assertIn('192.0.2.250', result.summary_before)
        self.assertNotIn('192.0.2.100', result.summary_before)
        self.assertEqual(result.summary_after, '')
        self.assertEqual(result.target_ip, '')
        self.assertEqual(result.ip_check, '')

    def test_resume_preserves_original_before_summary(self):
        previous = core.Result('earlier', '192.0.2.10', '확인불가', mode='apply',
                               config_sent=True, expected_nat='2', before_ip='192.0.2.100',
                               summary_before=core.safe_summary_text(summary()))
        result = self.run_script([{'replies': [summary('198.51.100.10', '2', 'NewSecret')]}],
                                 resume=[previous])[0]
        self.assertEqual(result.summary_before, previous.summary_before)
        self.assertIn('198.51.100.10', result.summary_after)
        self.assertEqual(result.ip_check, '일치')
        self.assertEqual(self.writes(), [])

    def test_new_write_clears_previous_recovery_current_ip(self):
        result = self.run_script([
            {'replies': [summary(), self.transient()]},
            {'replies': [summary('198.51.100.10', '2', 'WrongSecret'), self.transient()]},
            {'connect_error': self.transient('AP_LOGIN_TIMEOUT')},
        ])[0]
        self.assertEqual(result.status, '확인불가')
        self.assertEqual(result.after_ip, '')
        self.assertEqual(result.after_nat, '')
        self.assertEqual(result.ip_check, '')
        self.assertTrue(result.observed_at)
        self.assertIn('198.51.100.10', result.summary_after)


class ReportCaptureTests(unittest.TestCase):
    setUp = CoreTests.setUp
    run_job = CoreTests.run_job

    def test_safe_summary_api_exists(self):
        self.assertTrue(callable(getattr(core, 'safe_summary_text', None)))

    def test_normalized_summary_masks_keys_and_drops_echo_unknown_and_invalid_fields(self):
        text = ("config wips server 203.0.113.1 2 EchoSecret\n"
                + summary() + "\nunknown debug : UnknownSecret\n")
        safe = core.safe_summary_text(text, ('ControlSecret', 'APSecret', 'NewSecret'))
        self.assertIn('wips server ip : 192.0.2.100', safe)
        self.assertIn('wips mode : WIPS_SENSOR_MODE', safe)
        self.assertIn('wips nat : 2', safe)
        self.assertIn('wips sharedkey : [MASKED]', safe)
        for value in ('OldSecret', 'EchoSecret', 'UnknownSecret', 'config wips', 'ap01#'):
            self.assertNotIn(value, safe)
        bad = core.safe_summary_text(summary(ip='999.9.9.9', nat='2 extra').replace('WIPS_SENSOR_MODE', '<script>BAD</script>'))
        for value in ('999.9.9.9', '2 extra', '<script>', 'OldSecret'):
            self.assertNotIn(value, bad)
        duplicate = core.safe_summary_text(summary() + '\nwips server ip : 192.0.2.250')
        self.assertNotIn('wips server ip :', duplicate)
        self.assertEqual(core.safe_summary_text(safe), safe)

    def test_mode_field_never_duplicates_supplied_or_old_secret(self):
        text=summary(key='WIPS_SECRET_MODE').replace('WIPS_SENSOR_MODE','WIPS_SECRET_MODE')
        self.assertNotIn('WIPS_SECRET_MODE', core.safe_summary_text(text))
        self.assertNotIn('WIPS_SENSOR_MODE', core.safe_summary_text(summary(), ('SENSOR',)))

    def test_apply_captures_returned_keys_without_extra_commands_or_login_exports(self):
        result = self.run_job([summary(), '', summary('198.51.100.10', '2', 'NewSecret')])[0]
        self.assertEqual(result.status, '변경확인')
        self.assertEqual(result.target_ip, '198.51.100.10')
        self.assertEqual(result.ip_check, '일치')
        self.assertIn('192.0.2.100', result.summary_before)
        self.assertIn('198.51.100.10', result.summary_after)
        self.assertEqual(result.wips_mode, 'WIPS_SENSOR_MODE')
        self.assertEqual(ScriptedSession.commands, [core.SUMMARY_COMMAND, 'config wips server 198.51.100.10 2 NewSecret', core.SUMMARY_COMMAND])
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'results.csv';core.export_results(target,[result])
            exported=target.read_text('utf-8-sig')
        for secret in ('OldSecret', 'NewSecret', 'ControlSecret', 'APSecret'):
            self.assertNotIn(secret, repr(self.events))
        for password in ('ControlSecret', 'APSecret'):
            self.assertNotIn(password, exported)
        for key in ('OldSecret', 'NewSecret'):
            self.assertIn(key, exported)

    def test_verify_ip_ignores_bad_nat_but_preserves_safe_detail_and_uses_one_show(self):
        result=self.run_job([summary('198.51.100.10', 'unsupported', 'OldSecret')],mode='verify_ip',shared_key='')[0]
        self.assertEqual(result.status,'IP일치')
        self.assertIn('198.51.100.10',result.summary_before)
        self.assertNotIn('unsupported',result.summary_before)
        self.assertIn('wips sharedkey : OldSecret',result.summary_before)
        self.assertEqual(ScriptedSession.commands,[core.SUMMARY_COMMAND])

    def test_ip_match_is_independent_of_full_verification_and_unknown_write_clears_it(self):
        result=self.run_job([summary(), '', summary('198.51.100.10','2','********')])[0]
        self.assertEqual(result.status,'부분확인')
        self.assertEqual(result.ip_check,'일치')
        self.setUp()
        result=self.run_job([summary(), TimeoutError('lost')])[0]
        self.assertEqual(result.status,'확인불가')
        self.assertEqual(result.ip_check,'')
        self.assertEqual(result.summary_after,'')


class HostnameCaptureTests(unittest.TestCase):
    def test_hostname_config_and_result_fields_exist(self):
        cfg=config()
        self.assertTrue(hasattr(cfg,'lookup_hostnames'))
        self.assertEqual(cfg.ap_hostnames,{})
        self.assertEqual(core.Result('t','192.0.2.10','미실행').hostname,'')

    def run_host_job(self, *, hostname='', source='', failed=False, cfg=None):
        cfg=cfg or config()
        class Peer:
            ap_hostname=hostname
            hostname_source=source
            controller_ready=False
            def __init__(self,*args):pass
            def connect(self,ip):
                if failed:raise RuntimeError('failure')
            def execute(self,command):return summary()
            def leave_ap(self):self.controller_ready=True
            def close(self):self.controller_ready=False
        return core.Runner(cfg,lambda *a:None,lambda *a:False,threading.Event(),Peer).run('inspect')

    def test_csv_names_retained_for_failed_and_unexecuted_aps(self):
        cfg=config(ap_ips=['192.0.2.10','192.0.2.11'],
                   ap_hostnames={'192.0.2.10':'서울 AP-1','192.0.2.11':'F9_AP2'})
        result=self.run_host_job(failed=True,cfg=cfg)
        self.assertEqual([r.hostname for r in result],['서울 AP-1','F9_AP2'])
        self.assertEqual([r.hostname_source for r in result],['CSV','CSV'])
        self.assertEqual([r.status for r in result],['실패','미실행'])

    def test_controller_name_wins_and_csv_precedes_prompt(self):
        cfg=config(ap_hostnames={'192.0.2.10':'CSV_AP'})
        result=self.run_host_job(hostname='Actual_AP',source='컨트롤러 AP_NAME',cfg=cfg)[0]
        self.assertEqual((result.hostname,result.hostname_source),('Actual_AP','컨트롤러 AP_NAME'))
        result=self.run_host_job(hostname='Prompt_AP',source='AP 프롬프트',cfg=cfg)[0]
        self.assertEqual((result.hostname,result.hostname_source),('CSV_AP','CSV'))
        result=self.run_host_job(hostname='Actual_AP',source='컨트롤러 AP_NAME',failed=True,cfg=cfg)[0]
        self.assertEqual(result.hostname,'Actual_AP')

    def test_generic_or_credential_hostname_never_exported(self):
        for name,source in [('root','AP 프롬프트'),('AP','AP 프롬프트'),('ControlSecret','컨트롤러 AP_NAME'),('APSecret_AP','컨트롤러 AP_NAME'),('NewSecret','컨트롤러 AP_NAME')]:
            with self.subTest(name=name):
                result=self.run_host_job(hostname=name,source=source)[0]
                self.assertEqual(result.hostname,'')
        result=self.run_host_job(cfg=config(ap_hostnames={'192.0.2.10':'ControlSecret'}))[0]
        self.assertEqual(result.hostname,'')

    def test_hostname_map_validation_rejects_unsafe_or_unrelated_entries(self):
        for kwargs in ({'lookup_hostnames':1}, {'ap_hostnames':[]},
                       {'ap_hostnames':{'192.0.2.20':'AP2'}},
                       {'ap_hostnames':{'192.0.2.10':'bad\nname'}},
                       {'ap_hostnames':{'192.0.2.10':'=cmd'}},
                       {'ap_hostnames':{'192.0.2.10':'A'*129}}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                config(**kwargs).validate('inspect')
        self.assertEqual(core.safe_hostname(' 서울 AP-1 '),'서울 AP-1')
        self.assertEqual(core.safe_hostname('AP1\n'),'')

    def test_observed_time_exists_only_after_valid_named_ip_and_inspect_current_ip(self):
        result=self.run_host_job()[0]
        self.assertTrue(result.observed_at)
        from datetime import datetime
        self.assertIsNotNone(datetime.fromisoformat(result.observed_at).tzinfo)
        self.assertEqual(result.after_ip,result.before_ip)
        self.assertEqual(result.after_nat,result.before_nat)
        self.assertEqual(result.target_ip,'')
        failed=self.run_host_job(failed=True)[0]
        self.assertEqual(failed.observed_at,'')


class SharedKeyDisplayTests(unittest.TestCase):
    setUp = CoreTests.setUp
    run_job = CoreTests.run_job

    def test_reveal_requires_explicit_keyword(self):
        import inspect
        parameters=inspect.signature(core.safe_summary_text).parameters
        self.assertIn('reveal_shared_key',parameters)
        self.assertEqual(parameters['reveal_shared_key'].kind,inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameters['reveal_shared_key'].default,False)

    def test_explicit_reveal_preserves_device_value_special_chars_and_masks(self):
        for value in ('Demo<key>&"\'2026', 'KEY with spaces !@#', '********', '<hidden>', '[MASKED]'):
            with self.subTest(value=value):
                text=core.safe_summary_text(summary(key=value), (value,), reveal_shared_key=True)
                self.assertIn('wips sharedkey : '+value, text)
                self.assertEqual(core.safe_summary_text(text,reveal_shared_key=True),text)
                self.assertNotIn(value, core.safe_summary_text(summary(key=value))) if value != '[MASKED]' else None

    def test_invalid_key_is_not_reconstructed_or_exported(self):
        for value in ('', 'X'*257, 'BAD\x00VALUE', 'BAD\tVALUE', 'BAD\rVALUE', 'BAD\x1b[31mVALUE'):
            with self.subTest(value=repr(value)):
                text=core.safe_summary_text(summary(key=value),reveal_shared_key=True)
                self.assertIn('wips sharedkey : [UNAVAILABLE]',text)
                self.assertNotIn('BAD',text)
                self.assertNotIn('X'*257,text)
        text=core.safe_summary_text(summary(key='First')+'\nwips sharedkey : Second',reveal_shared_key=True)
        self.assertIn('wips sharedkey : [UNAVAILABLE]',text)
        self.assertNotIn('First',text);self.assertNotIn('Second',text)

    def test_inspect_and_verify_capture_device_key_without_target_fallback(self):
        for mode in ('inspect','verify_ip'):
            self.setUp()
            raw='login: ControlSecret\nPassword: APSecret\n'+summary(key='DeviceOldKey')
            result=self.run_job([raw],mode=mode)[0]
            self.assertIn('wips sharedkey : DeviceOldKey',result.summary_before)
            for forbidden in ('ControlSecret','APSecret','NewSecret','login:', 'Password:'):
                self.assertNotIn(forbidden,result.summary_before)
            self.assertNotIn('DeviceOldKey',repr(result)+repr(self.events))
        self.setUp()
        no_key='\n'.join(line for line in summary().splitlines() if 'sharedkey' not in line)
        result=self.run_job([no_key],mode='inspect')[0]
        self.assertNotIn('NewSecret',result.summary_before)
        self.assertNotIn('wips sharedkey',result.summary_before)

    def test_device_mask_is_shown_and_not_claimed_verified(self):
        for mask in ('********', '[MASKED]', '<hidden>'):
            with self.subTest(mask=mask):
                self.setUp()
                result=self.run_job([summary(key='OldKey'),'',summary('198.51.100.10','2',mask)])[0]
                self.assertEqual(result.status,'부분확인')
                self.assertEqual(result.key_check,'확인불가')
                self.assertIn('wips sharedkey : OldKey',result.summary_before)
                self.assertIn('wips sharedkey : '+mask,result.summary_after)
                self.assertNotIn('NewSecret',result.summary_after)


if __name__ == '__main__': unittest.main()
