"""Recovery over real loopback TCP/Telnet with persistent synthetic AP state.

No hardware is contacted. The fixture checks reconnect/read-before-write
orchestration; it does not emulate actual AP SSH encryption or firmware.
"""
from __future__ import annotations

import socket
import threading
import unittest

from wec_wips.core import RunConfig, Runner


class _RecoveryController:
    def __init__(self, scenario):
        self.scenario = scenario
        self.commands, self.errors, self.ap_logins = [], [], []
        self.connections = 0
        self.configs = {'192.0.2.10': ['192.0.2.200', '2', 'OldRecoveryKey'],
                        '192.0.2.11': ['192.0.2.201', '1', 'OldRecoveryKey']}
        self.stop = threading.Event()
        self.peer = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(5)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True,
                                       name='test-reconnecting-controller')

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        for resource in (self.peer, self.listener):
            if resource is not None:
                try: resource.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: resource.close()
                except OSError: pass
        self.thread.join(3)
        if self.thread.is_alive():
            raise AssertionError('Recovery fixture did not terminate')

    def _serve(self):
        while not self.stop.is_set():
            try: peer, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError:
                if not self.stop.is_set(): self.errors.append('listener_closed')
                return
            self.peer = peer
            self.connections += 1
            try:
                peer.settimeout(0.1)
                peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self._session(peer, self.connections)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Client can close a timed-out session at any point.
            except OSError as exc:
                if not self.stop.is_set(): self.errors.append(type(exc).__name__)
            except Exception as exc:
                self.errors.append(type(exc).__name__)
            finally:
                try: peer.close()
                except OSError: pass
                self.peer = None

    def _session(self, peer, connection):
        def send(text): peer.sendall(text.encode('utf-8'))
        state, buffer, current_ap = 'user', bytearray(), None
        send('Username: ')
        while not self.stop.is_set():
            try: chunk = peer.recv(4096)
            except socket.timeout: continue
            if not chunk: return
            buffer.extend(chunk)
            while b'\n' in buffer:
                line, _, rest = buffer.partition(b'\n')
                buffer = bytearray(rest)
                line = line.rstrip(b'\r').decode('utf-8')
                self.commands.append((connection, state, current_ap, line))
                if state == 'user':
                    assert line == 'testoperator', 'Unexpected fixture user'
                    send('\r\nPassword: '); state = 'controller_password'
                elif state == 'controller_password':
                    assert line == 'ControllerRecoverySecret', 'Unexpected fixture password'
                    send('\r\nWEC8500#'); state = 'controller'
                elif state == 'controller':
                    pieces = line.split()
                    assert len(pieces) == 4 and pieces[0] == 'ssh' and pieces[1] in self.configs and pieces[2:] == ['root', '50022'], 'Unexpected fixture SSH command'
                    current_ap = pieces[1]
                    self.ap_logins.append((connection, current_ap))
                    send(line + '\r\nPassword: '); state = 'ap_password'
                elif state == 'ap_password':
                    assert line == 'APRecoverySecret', 'Unexpected fixture AP password'
                    if self.scenario == 'auth_failure':
                        send('\r\nPermission denied\r\nWEC8500#'); state = 'controller'
                    else:
                        send('\r\nAP_RECOVERY#'); state = 'ap'
                elif line == 'show config wips summary':
                    if self.scenario in ('drop_before_write', 'cancel_backoff') and connection == 1: return
                    if self.scenario == 'timeout': continue
                    ip, nat, key = self.configs[current_ap]
                    if self.scenario == 'masked_after_write' and connection > 1: key = '********'
                    send(line + '\r\nwips mode ........ WIPS_SENSOR_MODE\r\n'
                         f'wips server ip ........ {ip}\r\nwips nat ........ {nat}\r\n'
                         f'wips sharedkey ........ {key}\r\nAP_RECOVERY#')
                elif line.startswith('config wips server '):
                    args = line.split()
                    assert len(args) == 6, 'Unexpected fixture config syntax'
                    self.configs[current_ap] = args[3:6]
                    if self.scenario in ('drop_after_write', 'masked_after_write') and connection == 1: return
                    send(line + '\r\nAP_RECOVERY#')
                elif line == 'exit':
                    if self.scenario == 'drop_exit' and connection == 1: return
                    send('exit\r\nConnection closed.\r\nWEC8500#'); state = 'controller'
                else:
                    raise AssertionError('Unexpected fixture AP command')


class RecoveryIntegrationTests(unittest.TestCase):
    def run_job(self, scenario, ap_ips=None, stop_on_retry=False, mode='apply'):
        events, stop = [], threading.Event()
        def emit(kind, data):
            events.append((kind, data))
            if stop_on_retry and kind == 'retry': stop.set()
        with _RecoveryController(scenario) as server:
            cfg = RunConfig(controller_ip='127.0.0.1', controller_port=server.port,
                            controller_user='testoperator', controller_password='ControllerRecoverySecret',
                            ap_ips=ap_ips or ['192.0.2.10'], ap_port=50022, ap_user='root',
                            ap_password='APRecoverySecret', server_ip='198.51.100.20',
                            shared_key='NewRecoveryKey', timeout=2)
            # Assignment also enables a behavioral red test against v1.3.
            cfg.auto_recover, cfg.max_retries, cfg.retry_delays = True, 2, (0.0, 0.0)
            results = Runner(cfg, emit, lambda *_: True, stop).run(mode)
            commands = list(server.commands)
            metrics = (server.connections, list(server.ap_logins))
        self.assertFalse(server.errors, server.errors)
        for secret in ('ControllerRecoverySecret', 'APRecoverySecret', 'OldRecoveryKey', 'NewRecoveryKey'):
            self.assertNotIn(secret, repr(events))
        return results, commands, metrics, events

    def config_lines(self, commands, ap_ip=None):
        return [line for _, state, ip, line in commands if state == 'ap' and line.startswith('config ')
                and (ap_ip is None or ip == ap_ip)]

    def test_applied_write_lost_reply_reconnects_reads_and_continues_without_duplicate_write(self):
        results, commands, metrics, events = self.run_job('drop_after_write', ['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in results], ['이미일치', '변경확인'])
        self.assertEqual(len(self.config_lines(commands, '192.0.2.10')), 1)
        self.assertEqual(len(self.config_lines(commands, '192.0.2.11')), 1)
        self.assertEqual(metrics, (2, [(1, '192.0.2.10'), (2, '192.0.2.10'), (2, '192.0.2.11')]))
        self.assertEqual(results[0].attempts, 2)
        self.assertTrue(any(k == 'retry' for k, _ in events))
        self.assertEqual([line for n, state, ip, line in commands if n == 2 and state == 'ap' and ip == '192.0.2.10'],
                         ['show config wips summary', 'exit'])

    def test_disconnect_before_first_read_reconnects_and_writes_once(self):
        results, commands, metrics, _ = self.run_job('drop_before_write')
        self.assertEqual(results[0].status, '변경확인')
        self.assertEqual(metrics[0], 2)
        self.assertEqual(len(self.config_lines(commands)), 1)
        self.assertEqual(results[0].attempts, 2)

    def test_authentication_failure_never_reconnects_or_writes(self):
        results, commands, metrics, events = self.run_job('auth_failure')
        self.assertEqual(results[0].status, '실패')
        self.assertEqual(metrics[0], 1)
        self.assertEqual(self.config_lines(commands), [])
        self.assertFalse(any(k == 'retry' for k, _ in events))

    def test_repeated_response_timeout_exhausts_three_sessions_then_skips_later_ap(self):
        results, commands, metrics, events = self.run_job('timeout', ['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in results], ['실패', '미실행'])
        self.assertEqual(metrics[0], 3)
        self.assertEqual([ip for _, ip in metrics[1]], ['192.0.2.10'] * 3)
        self.assertEqual(results[0].attempts, 3)
        self.assertEqual(len([1 for k, _ in events if k == 'retry']), 2)
        self.assertEqual(self.config_lines(commands), [])

    def test_cancel_on_recovery_event_does_not_open_another_session(self):
        results, commands, metrics, events = self.run_job('cancel_backoff', ['192.0.2.10', '192.0.2.11'], stop_on_retry=True)
        self.assertEqual(metrics[0], 1)
        self.assertEqual(self.config_lines(commands), [])
        self.assertEqual(results[0].status, '중지')
        self.assertEqual(results[1].status, '미실행')
        self.assertTrue(any(k == 'done' and d['cancelled'] for k, d in events))

    def test_masked_key_on_recovery_is_partial_and_never_blindly_reapplies(self):
        results, commands, metrics, _ = self.run_job('masked_after_write', ['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in results], ['부분확인', '미실행'])
        self.assertEqual(metrics[0], 2)
        self.assertEqual(len(self.config_lines(commands)), 1)
        self.assertTrue(results[0].config_sent)
        self.assertEqual(results[0].key_check, '확인불가')

    def test_lost_exit_reply_reconnects_reverifies_without_duplicate_configuration(self):
        results, commands, metrics, _ = self.run_job('drop_exit')
        self.assertEqual(results[0].status, '이미일치')
        self.assertEqual(results[0].controller_return, '복귀확인')
        self.assertEqual(metrics[0], 2)
        self.assertEqual(len(self.config_lines(commands)), 1)

    def test_read_only_ip_verification_recovers_without_any_config_transmission(self):
        results, commands, metrics, _ = self.run_job(
            'drop_before_write', ['192.0.2.10', '192.0.2.11'], mode='verify_ip')
        self.assertEqual([r.status for r in results], ['IP불일치', 'IP불일치'])
        self.assertEqual(metrics[0], 2)
        self.assertEqual(self.config_lines(commands), [])
        self.assertEqual([r.controller_return for r in results], ['복귀확인', '복귀확인'])
