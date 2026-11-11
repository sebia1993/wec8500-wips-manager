"""Actual loopback TELNET tests using only stdlib; no real devices contacted.

The TCP server emulates WEC8500 TELNET login and its nested AP SSH client.
Tests validate wire I/O and workflow ordering, not device firmware compatibility.
"""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from wec_wips.core import RunConfig, Runner, export_results

IAC, DO, DONT, WILL, WONT = 255, 253, 254, 251, 252
ECHO, SGA, UNKNOWN = 1, 3, 42


class _TelnetController:
    """One TCP connection, controller authentication and sequential AP CLIs."""
    def __init__(self, scenario='normal', negotiate=False, login_prompt='Username: '):
        self.scenario = scenario
        self.negotiate = negotiate
        self.login_prompt = login_prompt
        self.commands = []
        self.options = []
        self.errors = []
        self.tcp_connections = 0
        self.controller_logins = 0
        self.ap_connections = 0
        self.ap_exits = 0
        self.stop = threading.Event()
        self.peer = None
        self._wire_state = 'data'
        self._negotiation_verb = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True, name='test-telnet-controller')

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        for resource in (self.peer, self.listener):
            if resource is not None:
                try:
                    resource.close()
                except OSError:
                    pass  # Peer may have closed first. Assertions are not caught.
        self.thread.join(3)
        if self.thread.is_alive():
            raise AssertionError('Loopback TELNET server did not stop')

    def _send(self, text):
        self.peer.sendall(text.encode('utf-8') if isinstance(text, str) else text)

    def _initial_prompt(self):
        if self.negotiate:
            # Split IAC sequences and Username prompt across separate writes.
            for chunk in (bytes([IAC]), bytes([WILL]), bytes([ECHO]) + b'User',
                          bytes([IAC, WILL]), bytes([SGA]) + b'na',
                          bytes([IAC, WILL, UNKNOWN]), bytes([IAC, DO]),
                          bytes([UNKNOWN]), b'me: '):
                self._send(chunk)
                time.sleep(0.01)
        else:
            self._send(self.login_prompt)

    def _application_bytes(self, chunk):
        """Independent server-side decoder separates replies from credentials."""
        app = bytearray()
        for byte in chunk:
            if self._wire_state == 'data':
                if byte == IAC:
                    self._wire_state = 'iac'
                else:
                    app.append(byte)
            elif self._wire_state == 'iac':
                if byte in (DO, DONT, WILL, WONT):
                    self._negotiation_verb = byte
                    self._wire_state = 'option'
                elif byte == IAC:
                    app.append(byte)
                    self._wire_state = 'data'
                elif byte == 250:
                    self._wire_state = 'subnegotiation'
                else:
                    self._wire_state = 'data'
            elif self._wire_state == 'option':
                self.options.append((self._negotiation_verb, byte))
                self._wire_state = 'data'
            elif self._wire_state == 'subnegotiation':
                if byte == IAC:
                    self._wire_state = 'subnegotiation_iac'
            elif self._wire_state == 'subnegotiation_iac':
                self._wire_state = 'data' if byte == 240 else 'subnegotiation'
        return app

    def _serve(self):
        try:
            while not self.stop.is_set():
                try:
                    self.peer, _ = self.listener.accept()
                    self.tcp_connections += 1
                    break
                except socket.timeout:
                    continue
            if self.peer is None:
                return
            self.peer.settimeout(0.2)
            self.peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._initial_prompt()
            state = 'controller_user'
            buffer = bytearray()
            controller_user = ''
            current_ap = None
            ap_configs = {
                '192.0.2.10': ['192.0.2.200', '2', 'OldIntegrationKey'],
                '192.0.2.11': ['192.0.2.201', '2', 'OldIntegrationKey'],
            }

            def password_prompt():
                self._send(f'root@{current_ap} pass')
                time.sleep(0.01)
                self._send('word: ')

            while not self.stop.is_set():
                try:
                    chunk = self.peer.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    return
                buffer.extend(self._application_bytes(chunk))
                while b'\n' in buffer:
                    raw, remainder = buffer.split(b'\n', 1)
                    buffer = bytearray(remainder)
                    line = raw.rstrip(b'\r').decode('utf-8')
                    self.commands.append((state, line))
                    if state == 'controller_user':
                        controller_user = line
                        self.controller_logins += 1
                        self._send('\r\nPassword: ')
                        state = 'controller_password'
                    elif state == 'controller_password':
                        if controller_user != 'controlleradmin' or line != 'ControllerIntegrationSecret':
                            self._send('\r\nLogin incorrect\r\nUsername: ')
                            state = 'controller_user'
                        else:
                            self._send('\r\nWEC8500#')
                            state = 'controller'
                    elif state == 'controller':
                        if line == 'show ap summary':
                            self._send('show ap summary\r\n'
                                       'AP_ID CFG_NAME AP_NAME MAC_Address IPv4Addr State\r\n'
                                       '1 ap_1 LAB-AP10 00:11:22:33:44:10 192.0.2.10 1/1/5\r\n'
                                       '2 ap_2 LAB-AP11 00:11:22:33:44:11 192.0.2.11 1/1/5\r\n'
                                       'WEC8500#')
                            continue
                        pieces = line.split()
                        if len(pieces) != 4 or pieces[0] != 'ssh' or pieces[1] not in ap_configs or pieces[2:] != ['root', '50022']:
                            self._send('\r\n% Invalid command\r\nWEC8500#')
                            continue
                        current_ap = pieces[1]
                        self.ap_connections += 1
                        self._send(line + '\r\n')
                        if self.scenario == 'changed_ap_key':
                            self._send('WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n'
                                       'Host key verification failed.\r\nWEC8500#')
                        elif self.scenario == 'first_host_key' and current_ap == '192.0.2.10':
                            self._send(
                                f"The authenticity of host '{current_ap}' can't be established.\r\n"
                                'RSA key fingerprint is SHA256:SU5URUdSQVRJT05URVNUS0VZ.\r\n'
                                'Are you sure you want to continue connecting (yes/no)? ')
                            state = 'trust'
                        else:
                            password_prompt()
                            state = 'password'
                    elif state == 'trust':
                        if line == 'yes':
                            self._send('\r\n')
                            password_prompt()
                            state = 'password'
                        else:
                            self._send('\r\nHost key verification failed.\r\nWEC8500#')
                            state = 'controller'
                    elif state == 'password':
                        if self.scenario == 'auth_failure' or line != 'APIntegrationSecret':
                            self._send('\r\nPermission denied\r\nWEC8500#')
                            state = 'controller'
                        else:
                            self._send('\r\nAP_TEST#')
                            state = 'ap'
                    elif line == 'show config wips summary':
                        if self.scenario == 'bad_summary':
                            self._send(line + '\r\nUnrecognized summary format\r\nAP_TEST#')
                            continue
                        ip, nat, key = ap_configs[current_ap]
                        self._send(line + '\r\n'
                                   'wips mode ........ WIPS_SENSOR_MODE\r\n'
                                   f'wips server ip ........ {ip}\r\n'
                                   f'wips nat ........ {nat}\r\n'
                                   f'wips sharedkey ........ {key}\r\nAP_TEST#')
                    elif line.startswith('config wips server '):
                        args = line.split()
                        ap_configs[current_ap] = [args[3], args[4], args[5]]
                        if self.scenario == 'disconnect_after_write':
                            self.peer.close()
                            return
                        self._send(line + '\r\nAP_TEST#')
                    elif line == 'exit':
                        self.ap_exits += 1
                        if self.scenario == 'exit_failure':
                            self._send('exit\r\nAP_TEST#')
                        else:
                            self._send('exit\r\nConnection closed.\r\nWEC8500#')
                            state = 'controller'
                    else:
                        self._send('\r\n% Invalid command\r\nAP_TEST#')
        except Exception as exc:
            if not (self.stop.is_set() and isinstance(exc, OSError)):
                self.errors.append(type(exc).__name__)
        finally:
            if self.peer is not None:
                try:
                    self.peer.close()
                except OSError:
                    pass


class TelnetIntegrationTests(unittest.TestCase):
    def _run_job(self, mode='apply', scenario='normal', ap_ips=None,
                 auto_accept_ap_host_key=True, stop_on_error=True,
                 negotiate=False, login_prompt='Username: ',
                 controller_password='ControllerIntegrationSecret',
                 server_ip='198.51.100.20', shared_key='NewIntegrationKey'):
        events, confirmations = [], []
        def confirm(title, message):
            confirmations.append((title, message))
            return True  # Test-only approval; real app asks the local operator.
        with tempfile.TemporaryDirectory() as folder:
            with _TelnetController(scenario, negotiate, login_prompt) as server:
                cfg = RunConfig(
                    controller_ip='127.0.0.1', controller_port=server.port,
                    controller_user='controlleradmin', controller_password=controller_password,
                    ap_ips=ap_ips or ['192.0.2.10'], ap_port=50022, ap_user='root',
                    ap_password='APIntegrationSecret', server_ip=server_ip,
                    shared_key=shared_key, timeout=2,
                    auto_accept_ap_host_key=auto_accept_ap_host_key,
                    stop_on_error=stop_on_error,
                    auto_recover=False,  # v1.3 single-session regression; recovery has its own TCP fixture.
                )
                results = Runner(cfg, lambda kind, data: events.append((kind, data)),
                                 confirm, threading.Event()).run(mode)
                commands = list(server.commands)
            self.assertFalse(server.errors, server.errors)
            self.last_metrics = (server.tcp_connections, server.controller_logins,
                                 server.ap_connections, server.ap_exits)
            self.last_options = list(server.options)
            output = Path(folder) / 'results.csv'
            export_results(output, results)
            csv = output.read_text(encoding='utf-8-sig')
        return results, commands, events, confirmations, csv

    def test_telnet_inspect_does_not_send_configuration(self):
        results, commands, _, confirmations, _ = self._run_job('inspect')
        self.assertEqual(results[0].status, '조회완료')
        self.assertEqual(results[0].controller_return, '복귀확인')
        self.assertEqual(results[0].before_ip, '192.0.2.200')
        self.assertFalse(any(line.startswith('config ') for _, line in commands))
        self.assertEqual(commands[-1], ('ap', 'exit'))
        self.assertEqual(confirmations, [])

    def test_telnet_then_ap_ssh_apply_verifies_all_values(self):
        results, commands, _, _, _ = self._run_job()
        self.assertEqual(results[0].status, '변경확인')
        self.assertEqual(results[0].after_ip, '198.51.100.20')
        self.assertEqual(results[0].after_nat, '2')
        self.assertEqual(results[0].key_check, '일치')
        self.assertEqual([line for state, line in commands if state == 'ap'], [
            'show config wips summary',
            'config wips server 198.51.100.20 2 NewIntegrationKey',
            'show config wips summary', 'exit',
        ])

    def test_two_aps_share_one_telnet_login_with_exact_yes_password_exit_sequence(self):
        results, commands, _, confirmations, _ = self._run_job(
            scenario='first_host_key', ap_ips=['192.0.2.10', '192.0.2.11'])
        self.assertEqual([r.status for r in results], ['변경확인', '변경확인'])
        self.assertEqual([r.controller_return for r in results], ['복귀확인', '복귀확인'])
        self.assertEqual(self.last_metrics, (1, 1, 2, 2))
        self.assertEqual(commands, [
            ('controller_user', 'controlleradmin'),
            ('controller_password', 'ControllerIntegrationSecret'),
            ('controller', 'ssh 192.0.2.10 root 50022'),
            ('trust', 'yes'),
            ('password', 'APIntegrationSecret'),
            ('ap', 'show config wips summary'),
            ('ap', 'config wips server 198.51.100.20 2 NewIntegrationKey'),
            ('ap', 'show config wips summary'),
            ('ap', 'exit'),
            ('controller', 'ssh 192.0.2.11 root 50022'),
            ('password', 'APIntegrationSecret'),
            ('ap', 'show config wips summary'),
            ('ap', 'config wips server 198.51.100.20 2 NewIntegrationKey'),
            ('ap', 'show config wips summary'),
            ('ap', 'exit'),
        ])
        self.assertEqual(confirmations, [])

    def test_ap_host_key_manual_setting_asks_then_sends_yes(self):
        results, commands, _, confirmations, _ = self._run_job(
            scenario='first_host_key', auto_accept_ap_host_key=False)
        self.assertEqual(results[0].status, '변경확인')
        self.assertEqual(len(confirmations), 1)
        self.assertIn('AP', confirmations[0][0])
        self.assertEqual(commands[3:5], [('trust', 'yes'), ('password', 'APIntegrationSecret')])

    def test_exit_failure_stops_batch_even_when_continue_on_error_selected(self):
        results, commands, _, _, _ = self._run_job(
            scenario='exit_failure', ap_ips=['192.0.2.10', '192.0.2.11'], stop_on_error=False)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].status, '복귀실패')
        self.assertEqual(results[0].controller_return, '미확인')
        self.assertEqual(results[0].after_ip, '198.51.100.20')
        self.assertEqual(results[0].key_check, '일치')
        self.assertEqual(results[1].status, '미실행')
        self.assertEqual(self.last_metrics, (1, 1, 1, 1))
        self.assertFalse(any('192.0.2.11' in line for _, line in commands))
        self.assertEqual(len([line for _, line in commands if line.startswith('config ')]), 1)

    def test_ap_auth_failure_cannot_write_controller(self):
        results, commands, _, _, _ = self._run_job(scenario='auth_failure')
        self.assertEqual(results[0].status, '실패')
        self.assertFalse(any(line.startswith(('config ', 'show ')) for _, line in commands))

    def test_changed_ap_host_key_never_sends_yes_password_or_change(self):
        results, commands, _, confirmations, _ = self._run_job(scenario='changed_ap_key')
        self.assertEqual(results[0].status, '실패')
        self.assertFalse(any(state in ('password', 'trust', 'ap') for state, _ in commands))
        self.assertEqual(confirmations, [])

    def test_disconnect_after_write_is_unknown_and_not_retried(self):
        results, commands, _, _, _ = self._run_job(scenario='disconnect_after_write')
        self.assertEqual(results[0].status, '확인불가')
        self.assertEqual(len([line for _, line in commands if line.startswith('config ')]), 1)

    def test_exports_include_queried_wips_keys_but_not_login_credentials(self):
        results, _, events, confirmations, csv = self._run_job(
            scenario='first_host_key', auto_accept_ap_host_key=False)
        self.assertEqual(results[0].status, '변경확인')
        diagnostic_data = repr(results) + repr(events) + repr(confirmations)
        for secret in ('ControllerIntegrationSecret', 'APIntegrationSecret',
                       'OldIntegrationKey', 'NewIntegrationKey'):
            self.assertNotIn(secret, diagnostic_data)
        for secret in ('ControllerIntegrationSecret', 'APIntegrationSecret'):
            self.assertNotIn(secret, csv)
        self.assertIn('wips sharedkey : OldIntegrationKey', csv)
        self.assertIn('wips sharedkey : NewIntegrationKey', csv)

    def test_wrong_controller_password_then_relogin_stops_without_retry(self):
        results, commands, _, _, _ = self._run_job(controller_password='WrongControllerSecret')
        self.assertEqual(results[0].status, '실패')
        self.assertEqual(commands, [('controller_user', 'controlleradmin'),
                                    ('controller_password', 'WrongControllerSecret')])
        self.assertEqual(self.last_metrics, (1, 1, 0, 0))

    def test_fragmented_telnet_negotiation_and_prompt_keep_credentials_separate(self):
        results, commands, _, _, _ = self._run_job(mode='inspect', negotiate=True)
        self.assertEqual(results[0].status, '조회완료')
        self.assertEqual(commands[:2], [('controller_user', 'controlleradmin'),
                                        ('controller_password', 'ControllerIntegrationSecret')])
        self.assertTrue({(DO, ECHO), (DO, SGA), (DONT, UNKNOWN), (WONT, UNKNOWN)}.issubset(self.last_options), self.last_options)
        self.assertEqual(self.last_metrics, (1, 1, 1, 1))

    def test_login_and_id_controller_prompt_variants(self):
        for prompt in ('login: ', 'ID: '):
            with self.subTest(prompt=prompt):
                results, commands, _, _, _ = self._run_job(mode='inspect', login_prompt=prompt)
                self.assertEqual(results[0].status, '조회완료')
                self.assertEqual(commands[0], ('controller_user', 'controlleradmin'))

    def test_verify_ip_mixed_results_continue_without_key_or_configuration(self):
        results, commands, _, _, _ = self._run_job(
            mode='verify_ip', ap_ips=['192.0.2.10', '192.0.2.11'],
            server_ip='192.0.2.201', shared_key='', stop_on_error=True)
        # A first mismatch is a comparison result, not an error that skips AP 2.
        self.assertEqual([r.status for r in results], ['IP불일치', 'IP일치'])
        self.assertEqual([r.target_ip for r in results], ['192.0.2.201', '192.0.2.201'])
        self.assertEqual([r.after_ip for r in results], ['192.0.2.200', '192.0.2.201'])
        self.assertEqual([r.ip_check for r in results], ['불일치', '일치'])
        self.assertEqual([r.controller_return for r in results], ['복귀확인', '복귀확인'])
        self.assertEqual(self.last_metrics, (1, 1, 2, 2))
        self.assertEqual(commands, [
            ('controller_user', 'controlleradmin'),
            ('controller_password', 'ControllerIntegrationSecret'),
            ('controller', 'ssh 192.0.2.10 root 50022'),
            ('password', 'APIntegrationSecret'),
            ('ap', 'show config wips summary'),
            ('ap', 'exit'),
            ('controller', 'ssh 192.0.2.11 root 50022'),
            ('password', 'APIntegrationSecret'),
            ('ap', 'show config wips summary'),
            ('ap', 'exit'),
        ])
        self.assertFalse(any(line.startswith('config ') for _, line in commands))

    def test_verify_ip_invalid_summary_stops_batch_without_configuration(self):
        results, commands, _, _, _ = self._run_job(
            mode='verify_ip', scenario='bad_summary',
            ap_ips=['192.0.2.10', '192.0.2.11'], server_ip='192.0.2.201', shared_key='')
        self.assertEqual([r.status for r in results], ['실패', '미실행'])
        self.assertEqual(results[0].controller_return, '복귀확인')
        self.assertEqual(self.last_metrics, (1, 1, 1, 1))
        self.assertEqual(len([line for _, line in commands if line == 'show config wips summary']), 1)
        self.assertFalse(any(line.startswith('config ') or '192.0.2.11' in line for _, line in commands))


if __name__ == '__main__':
    unittest.main()
