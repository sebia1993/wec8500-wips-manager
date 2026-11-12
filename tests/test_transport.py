"""In-memory transport tests use protocol time, not host scheduling deadlines."""
from __future__ import annotations

from collections import deque
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import time
import unittest

from transport_test_clock import ProtocolClock, ProtocolEvent


class Peer:
    def __init__(self, replies=None, initial=None, *, monotonic=None):
        self.pending = deque(initial or [b"Samsung controller\r\nUser", b"name:"])
        self.replies = replies or {}
        self.sent = []
        self.closed = False
        self.ready_at = 0.0
        self.timeout = None
        # Other tests importing Peer retain real time unless explicitly opted in.
        self.monotonic = monotonic or time.monotonic
        self.peer = self
        self.connect_count = 0
        self.kwargs = None

    def recv_ready(self):
        return bool(self.pending) and self.monotonic() >= self.ready_at

    def recv(self, count):
        item = self.pending.popleft()
        if isinstance(item, tuple):
            delay, payload = item
            self.ready_at = self.monotonic() + delay
            return payload
        return item

    def sendall(self, data):
        if isinstance(data, bytes):
            data = data.decode()
        self.sent.append(data)
        value = self.replies.get(data, [])
        self.pending.extend(value)

    def settimeout(self, value):
        self.timeout = value

    def close(self):
        self.closed = True


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict("os.environ", {"LOCALAPPDATA": self.tmp.name})
        self.env.start()
        self.cfg = SimpleNamespace(
            controller_ip="192.0.2.1", controller_port=23,
            controller_user="admin", controller_password="CtlPW!",
            ap_port=50022, ap_user="admin", ap_password="APsecret#",
            timeout=0.5,
            auto_accept_ap_host_key=False,
        )
        self.clock = ProtocolClock()
        self.stop = ProtocolEvent(self.clock)
        # Patch the module reference, not time.monotonic on the shared time module.
        # Real socket integration/GUI tests keep their own actual clock.
        clock_patch = patch("wec_wips.transport.time", self.clock)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)
        self.prompts = []

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def make(self, peer, approval=True):
        from wec_wips.transport import Session
        peer.monotonic = self.clock.monotonic
        def connect(**kwargs):
            peer.connect_count += 1
            peer.kwargs = kwargs
            return peer

        connector = patch("wec_wips.transport.TelnetChannel.connect", side_effect=connect)
        connector.start()
        self.addCleanup(connector.stop)

        def confirm(title, message):
            self.prompts.append((title, message))
            return approval

        return Session(self.cfg, self.stop, confirm), peer

    def peer(self, **overrides):
        replies = {
            "admin\n": [b"Password:"],
            "CtlPW!\n": [b"\r\nWEC8500#"],
            "ssh 192.0.2.11 admin 50022\n": [b"ssh 192.0.2.11 admin 50022\r\nPass", b"word:"],
            "APsecret#\n": [b"\r\nAPsecret#\r\n", (0.03, b"\x1b[32mAP_11"), b"#\x1b[0m"],
            "show config wips summary\n": [b"show config wips summary\r\nwips server ip ..... 192.0.2.55\r\nAP_11#"],
            "exit\n": [b"exit\r\nConnection to 192.0.2.11 closed.\r\nWEC8500#"],
        }
        replies.update(overrides)
        return Peer(replies)

    def test_module_implements_session(self):
        from importlib.util import find_spec
        self.assertIsNotNone(find_spec("wec_wips.transport"), "transport is not implemented")

    def test_fragmented_login_and_exact_prompt(self):
        session, client = self.make(self.peer())
        session.connect("192.0.2.11")
        output = session.execute("show config wips summary")
        self.assertIn("192.0.2.55", output)
        self.assertEqual(client.kwargs["port"], 23)
        self.assertEqual(client.peer.sent[:2], ["admin\n", "CtlPW!\n"])
        self.assertEqual(client.peer.sent.count("APsecret#\n"), 1)
        session.close()
        self.assertTrue(client.peer.closed)

    def test_return_to_controller_during_login_never_becomes_ap(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"APsecret#\n": [b"Permission denied\r\nWEC8500#"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.execute("config wips server 192.0.2.50 1 Key!")
        self.assertFalse(any(s.startswith("config ") for s in peer.sent))

    def test_return_to_controller_after_command_blocks_next_send(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"show config wips summary\n": [b"Connection closed\r\nWEC8500#"]})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.execute("show config wips summary")
        with self.assertRaises(TransportError):
            session.execute("config wips server 192.0.2.50 1 Key!")
        self.assertFalse(any(s.startswith("config ") for s in peer.sent))

    def test_unknown_ap_host_key_requires_explicit_confirmation(self):
        peer = self.peer(**{
            "ssh 192.0.2.11 admin 50022\n": [
                b"The authenticity of host cannot be established.\r\nRSA key fingerprint is SHA256:abc123.\r\nAre you sure you want to continue connecting (yes/no)? "],
            "yes\n": [b"Password:"],
        })
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("SHA256:abc123", self.prompts[0][1])
        self.assertIn("yes\n", peer.sent)

    def test_unknown_ap_host_key_rejection_does_not_send_password(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [
            b"RSA key fingerprint is SHA256:abc123\r\nContinue connecting (yes/no)?"]})
        session, _ = self.make(peer, approval=False)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertNotIn("APsecret#\n", peer.sent)
        self.assertNotIn("yes\n", peer.sent)

    def test_missing_fingerprint_not_autoaccepted(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [b"Continue connecting (yes/no)?"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertNotIn("yes\n", peer.sent)

    def test_changed_ap_host_key_is_rejected_without_confirmation(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [
            b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nWEC8500#"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertEqual(self.prompts, [])
        self.assertNotIn("APsecret#\n", peer.sent)

    def test_timeout_closes_session_and_error_contains_no_received_secrets(self):
        from wec_wips.transport import TransportError
        self.cfg.timeout = 0.08
        peer = self.peer(**{"APsecret#\n": [b"unknown response secret-leak"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError) as caught:
            session.connect("192.0.2.11")
        self.assertNotIn("secret-leak", str(caught.exception))
        self.assertNotIn("APsecret", str(caught.exception))
        self.assertTrue(peer.closed)

    def test_password_is_never_retried(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"APsecret#\n": [b"Password:"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertEqual(peer.sent.count("APsecret#\n"), 1)

    def test_stop_before_connect_sends_nothing(self):
        from wec_wips.transport import Cancelled
        peer = self.peer()
        session, _ = self.make(peer)
        self.stop.set()
        with self.assertRaises(Cancelled):
            session.connect("192.0.2.11")
        self.assertEqual(peer.sent, [])

    def test_command_newline_and_username_injection_rejected(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.execute("show config wips summary\nreboot")
        self.assertNotIn("show config wips summary\nreboot\n", peer.sent)
        self.cfg.ap_user = "admin;reboot"
        session, _ = self.make(self.peer())
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")

    def test_controller_login_username_password_sent_once(self):
        for initial in ([b"login:"], [b"User name:"], [b"ID:"]):
            with self.subTest(initial=initial):
                peer = self.peer()
                peer.pending = deque(initial)
                session, client = self.make(peer)
                session.connect("192.0.2.11")
                self.assertEqual(peer.sent[:3], ["admin\n", "CtlPW!\n", "ssh 192.0.2.11 admin 50022\n"])
                self.assertEqual(peer.sent.count("admin\n"), 1)
                self.assertEqual(peer.sent.count("CtlPW!\n"), 1)
                self.assertEqual(self.prompts, [])
                session.close()

    def test_controller_password_before_username_fails_without_password(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        peer.pending = deque([b"Password:"])
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertEqual(peer.sent, [])
        self.assertTrue(peer.closed)

    def test_controller_repeated_login_or_password_never_retries(self):
        from wec_wips.transport import TransportError
        for response in (b"Username:", b"Password:", b"Access denied. CtlPW! APsecret#"):
            with self.subTest(response=response):
                peer = self.peer(**{"CtlPW!\n": [response]})
                session, _ = self.make(peer)
                with self.assertRaises(TransportError) as caught:
                    session.connect("192.0.2.11")
                self.assertEqual(peer.sent.count("admin\n"), 1)
                self.assertEqual(peer.sent.count("CtlPW!\n"), 1)
                self.assertFalse(any(x.startswith("ssh ") for x in peer.sent))
                self.assertNotIn("CtlPW", str(caught.exception))
                self.assertNotIn("APsecret", str(caught.exception))
                self.assertTrue(peer.closed)

    def test_controller_initial_prompt_without_login_is_rejected(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        peer.pending = deque([b"WEC8500#"])
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertEqual(peer.sent, [])

    def test_cancel_while_waiting_for_command_closes_connection(self):
        from wec_wips.transport import Cancelled
        peer = self.peer(**{"show config wips summary\n": []})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        self.clock.call_later(0.03, self.stop.set)
        with self.assertRaises(Cancelled):
            session.execute("show config wips summary")
        self.assertTrue(peer.closed)

    def test_key_echo_ending_hash_not_treated_as_complete_command(self):
        peer = self.peer(**{"show config wips summary\n": [
            (0.03, b"wips sharedkey .... Secret#\r\n"),
            b"wips server ip .... 192.0.2.55\r\nAP_11#"]})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        self.assertIn("192.0.2.55", session.execute("show config wips summary"))

    def test_unsolicited_controller_prompt_blocks_command_send(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        peer.pending.append(b"\r\nWEC8500#")
        with self.assertRaises(TransportError):
            session.execute("config wips server 192.0.2.50 1 Key!")
        self.assertFalse(any(s.startswith("config ") for s in peer.sent))

    def test_response_size_limit(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"show config wips summary\n": [b"X" * (1024 * 1024 + 1)]})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.execute("show config wips summary")
        self.assertTrue(peer.closed)

    def test_auto_yes_accepts_new_host_question_without_fingerprint(self):
        self.cfg.auto_accept_ap_host_key = True
        for question in (b"Continue connecting (yes/no)?", b"Are you sure you want to continue connecting (yes or NO): "):
            with self.subTest(question=question):
                peer = self.peer(**{
                    "ssh 192.0.2.11 admin 50022\n": [question],
                    "yes\n": [b"Password:"],
                })
                session, _ = self.make(peer, approval=False)
                session.connect("192.0.2.11")
                self.assertIn("yes\n", peer.sent)
                self.assertEqual(self.prompts, [])
                self.assertLess(peer.sent.index("yes\n"), peer.sent.index("APsecret#\n"))
                session.close()

    def test_auto_yes_rejects_unrelated_or_destructive_question(self):
        from wec_wips.transport import TransportError
        self.cfg.auto_accept_ap_host_key = True
        for question in (b"Reset configuration (yes/no)?", b"Continue (yes or NO):",
                         b"Delete files (yes/no)?", b"Reboot (yes/no)?"):
            with self.subTest(question=question):
                peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [question],
                                    "yes\n": [b"Password:"]})
                session, _ = self.make(peer)
                with self.assertRaises(TransportError):
                    session.connect("192.0.2.11")
                self.assertNotIn("yes\n", peer.sent)
                self.assertNotIn("APsecret#\n", peer.sent)
                self.assertTrue(peer.closed)

    def test_auto_yes_accepts_explicit_known_hosts_add_question(self):
        self.cfg.auto_accept_ap_host_key = True
        peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [
            b"Add this host to known hosts (yes/no)?"], "yes\n": [b"Password:"]})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        self.assertIn("yes\n", peer.sent)

    def test_auto_yes_still_rejects_changed_host_key(self):
        from wec_wips.transport import TransportError
        self.cfg.auto_accept_ap_host_key = True
        peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [
            b"REMOTE HOST IDENTIFICATION HAS CHANGED!\r\nContinue (yes/no)?"]})
        session, _ = self.make(peer)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.11")
        self.assertNotIn("yes\n", peer.sent)
        self.assertNotIn("APsecret#\n", peer.sent)

    def test_auto_yes_rejects_alternate_host_key_mismatch_warnings(self):
        from wec_wips.transport import TransportError
        self.cfg.auto_accept_ap_host_key = True
        for warning in (
            b"Host key for 192.0.2.11 has changed",
            b"WARNING: POSSIBLE DNS SPOOFING DETECTED!",
            b"Host key mismatch",
            b"WARNING: the RSA host key for 192.0.2.11 differs from the key",
        ):
            with self.subTest(warning=warning):
                peer = self.peer(**{"ssh 192.0.2.11 admin 50022\n": [warning + b"\r\nContinue (yes/no)?"],
                                    "yes\n": [b"Password:"]})
                session, _ = self.make(peer)
                with self.assertRaises(TransportError):
                    session.connect("192.0.2.11")
                self.assertNotIn("yes\n", peer.sent)

    def test_controller_ready_is_false_if_underlying_channel_is_dead(self):
        peer = self.peer()
        session, client = self.make(peer)
        session.connect("192.0.2.11")
        session.leave_ap()
        peer.closed = True
        self.assertFalse(session.controller_ready)

    def test_two_aps_reuse_one_controller_with_verified_exit(self):
        peer = self.peer()
        session, client = self.make(peer)
        self.assertFalse(session.controller_ready)
        session.connect("192.0.2.11")
        self.assertFalse(session.controller_ready)
        session.execute("show config wips summary")
        session.leave_ap()
        self.assertTrue(session.controller_ready)
        peer.replies["ssh 192.0.2.12 admin 50022\n"] = [b"Password:"]
        peer.replies["APsecret#\n"] = [b"\r\nAP_12#"]
        peer.replies["show config wips summary\n"] = [b"wips server ip ... 192.0.2.55\r\nAP_12#"]
        session.connect("192.0.2.12")
        session.execute("show config wips summary")
        session.leave_ap()
        self.assertTrue(session.controller_ready)
        self.assertEqual(client.connect_count, 1)
        self.assertEqual(peer.sent.count("exit\n"), 2)
        self.assertEqual([s for s in peer.sent if s.startswith("ssh ")], [
            "ssh 192.0.2.11 admin 50022\n", "ssh 192.0.2.12 admin 50022\n"])
        self.assertFalse(peer.closed)

    def test_connect_without_exit_does_not_start_nested_ssh(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        session, client = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.connect("192.0.2.12")
        self.assertNotIn("ssh 192.0.2.12 admin 50022\n", peer.sent)
        self.assertEqual(client.connect_count, 1)

    def test_exit_without_controller_prompt_closes_and_prevents_reconnect(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"exit\n": [b"exit\r\nAP_11#"]})
        session, client = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.leave_ap()
        self.assertFalse(session.controller_ready)
        self.assertTrue(peer.closed)
        with self.assertRaises(TransportError):
            session.connect("192.0.2.12")
        self.assertEqual(client.connect_count, 1)
        self.assertNotIn("ssh 192.0.2.12 admin 50022\n", peer.sent)

    def test_exit_to_wrong_controller_prompt_is_not_ready(self):
        from wec_wips.transport import TransportError
        peer = self.peer(**{"exit\n": [b"exit\r\nWEC8500/configure#"]})
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        with self.assertRaises(TransportError):
            session.leave_ap()
        self.assertFalse(session.controller_ready)


    def test_pending_blank_chunks_do_not_block_command_or_exit(self):
        peer = self.peer()
        session, _ = self.make(peer)
        session.connect("192.0.2.11")
        peer.pending.extend([b"\r", b"\n \t\r\n"])
        self.assertIn("192.0.2.55", session.execute("show config wips summary"))
        peer.pending.extend([b"\r\n", b" \t"])
        session.leave_ap()
        peer.pending.extend([b"\r\n", b" \t"])
        self.assertTrue(session.controller_ready)
        self.assertEqual(peer.sent.count("show config wips summary\n"), 1)
        self.assertEqual(peer.sent.count("exit\n"), 1)

    def test_blank_then_unexpected_prompt_still_blocks_command(self):
        from wec_wips.transport import TransportError
        for unexpected in (b"WEC8500#", b"Host key mismatch", b"background message", b"\x1b[0m"):
            with self.subTest(unexpected=unexpected):
                peer = self.peer()
                session, _ = self.make(peer)
                session.connect("192.0.2.11")
                peer.pending.extend([b"\r\n", unexpected])
                with self.assertRaises(TransportError) as caught:
                    session.execute("config wips server 192.0.2.50 1 Key!")
                self.assertFalse(caught.exception.retryable)
                self.assertIn(caught.exception.code, ("UNEXPECTED_DATA", "HOST_KEY_CHANGED"))
                self.assertFalse(any(s.startswith("config ") for s in peer.sent))
                self.assertTrue(peer.closed)

    def test_nonblank_controller_data_invalidates_readiness_permanently(self):
        peer = self.peer()
        session, _ = self.make(peer)
        session.connect('192.0.2.11')
        session.leave_ap()
        peer.pending.extend([b'\r\n', b'background data'])
        self.assertFalse(session.controller_ready)
        self.assertFalse(session.controller_ready)
        self.assertTrue(peer.closed)

    def test_error_metadata_is_readonly_and_cancel_is_not_retryable(self):
        from wec_wips.transport import Cancelled, TransportError
        error = TransportError("safe", code="COMMAND_TIMEOUT", retryable=True)
        self.assertEqual(str(error), "safe")
        self.assertEqual(error.code, "COMMAND_TIMEOUT")
        self.assertTrue(error.retryable)
        with self.assertRaises(AttributeError): error.code = "changed"
        with self.assertRaises(AttributeError): error.retryable = False
        self.assertEqual(TransportError("old signature").code, "TRANSPORT_ERROR")
        self.assertFalse(TransportError("old signature").retryable)
        self.assertFalse(Cancelled("stopped").retryable)

    def test_observer_has_static_stage_and_empty_activity_without_secrets(self):
        events = []
        peer = self.peer()
        session, _ = self.make(peer)
        self.assertTrue(hasattr(session, "set_observer"))
        session.set_observer(lambda kind, data: events.append((kind, data)))
        session.connect("192.0.2.11")
        session.execute("show config wips summary")
        session.leave_ap()
        stages = [data['stage'] for kind, data in events if kind == 'stage']
        self.assertEqual(stages, ['컨트롤러 연결', '컨트롤러 로그인', 'AP 로그인', '컨트롤러 복귀'])
        self.assertTrue(any(kind == 'activity' for kind, _ in events))
        self.assertTrue(all(data == {} for kind, data in events if kind == 'activity'))
        text = repr(events)
        for secret in (self.cfg.controller_password, self.cfg.ap_password, "192.0.2.55", "show config"):
            self.assertNotIn(secret, text)

    def test_connection_errors_are_retryable_without_raw_exception(self):
        from wec_wips.transport import Session, TransportError
        for error, expected in ((TimeoutError('private detail'), 'CONTROLLER_CONNECT_TIMEOUT'),
                                (ConnectionRefusedError('private detail'), 'CONTROLLER_CONNECT_FAILED')):
            with self.subTest(expected=expected):
                session = Session(self.cfg, self.stop, lambda *_: True)
                with patch('wec_wips.transport.TelnetChannel.connect', side_effect=error):
                    with self.assertRaises(TransportError) as caught:
                        session.connect('192.0.2.11')
                self.assertEqual(caught.exception.code, expected)
                self.assertTrue(caught.exception.retryable)
                self.assertNotIn('private detail', str(caught.exception))

    def test_controller_and_ap_login_timeout_metadata(self):
        from wec_wips.transport import TransportError
        for replies, expected in (({'CtlPW!\n': [b'waiting']}, 'CONTROLLER_LOGIN_TIMEOUT'),
                                  ({'APsecret#\n': [b'waiting']}, 'AP_LOGIN_TIMEOUT'),
                                  ({'APsecret#\n': [b'Connection refused']}, 'AP_CONNECT_FAILED')):
            with self.subTest(expected=expected):
                self.cfg.timeout = 0.2
                peer = self.peer(**replies)
                session, _ = self.make(peer)
                with self.assertRaises(TransportError) as caught:
                    session.connect('192.0.2.11')
                self.assertEqual(caught.exception.code, expected)
                self.assertTrue(caught.exception.retryable)

    def test_command_return_and_connection_drop_metadata(self):
        from wec_wips.transport import TransportError
        cases = (({'show config wips summary\n': []}, 'execute', 'COMMAND_TIMEOUT'),
                 ({'exit\n': []}, 'leave_ap', 'RETURN_TIMEOUT'),
                 ({'show config wips summary\n': [b'Connection closed\r\nWEC8500#']}, 'execute', 'CONNECTION_CLOSED'))
        for replies, action, expected in cases:
            with self.subTest(expected=expected):
                peer = self.peer(**replies)
                session, _ = self.make(peer)
                session.connect('192.0.2.11')
                self.cfg.timeout = 0.1
                with self.assertRaises(TransportError) as caught:
                    if action == 'execute': session.execute('show config wips summary')
                    else: session.leave_ap()
                self.assertEqual(caught.exception.code, expected)
                self.assertTrue(caught.exception.retryable)
                self.cfg.timeout = 0.5

    def test_socket_io_error_is_retryable_but_auth_and_keys_are_not(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        session, _ = self.make(peer)
        session.connect('192.0.2.11')
        with patch.object(peer, 'sendall', side_effect=OSError('secret socket detail')):
            with self.assertRaises(TransportError) as caught:
                session.execute('show config wips summary')
        self.assertEqual(caught.exception.code, 'IO_ERROR')
        self.assertTrue(caught.exception.retryable)
        self.assertNotIn('secret socket detail', str(caught.exception))
        for response, code in ((b'Permission denied', 'AP_AUTH_FAILED'), (b'Host key mismatch', 'HOST_KEY_CHANGED')):
            peer = self.peer(**{'APsecret#\n': [response]})
            session, _ = self.make(peer)
            with self.assertRaises(TransportError) as caught:
                session.connect('192.0.2.11')
            self.assertFalse(caught.exception.retryable)
            self.assertEqual(caught.exception.code, code)

    def test_dead_channel_is_retryable_and_observer_errors_do_not_break_work(self):
        from wec_wips.transport import TransportError
        peer = self.peer()
        session, _ = self.make(peer)
        session.set_observer(lambda *_: (_ for _ in ()).throw(RuntimeError('observer failure')))
        session.connect('192.0.2.11')
        peer.closed = True
        with self.assertRaises(TransportError) as caught:
            session.execute('show config wips summary')
        self.assertEqual(caught.exception.code, 'CONNECTION_CLOSED')
        self.assertTrue(caught.exception.retryable)


if __name__ == "__main__":
    unittest.main()
