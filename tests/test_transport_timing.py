"""The in-memory transport fixture must separate protocol time from host pauses.

No product timeouts are changed. Session still executes its real parsing,
state machine, deadline and cancellation code; only the unit fixture's clock
and wait boundary are simulated. Socket integration tests use real time.
"""
from contextlib import contextmanager
import time
import unittest
from unittest.mock import patch

import test_transport as cases
from wec_wips import transport


@contextmanager
def fixture():
    case = cases.TransportTests('test_fragmented_login_and_exact_prompt')
    case.setUp()
    try:
        yield case
    finally:
        try:
            case.tearDown()
        finally:
            case.doCleanups()


class TransportTimingTests(unittest.TestCase):
    def test_in_memory_login_survives_host_pause_without_extending_deadline(self):
        # Break caught: real scheduling time consumes a purely synthetic peer's
        # deadline even though its reply is already in memory and ready to read.
        with fixture() as case:
            peer = case.peer()
            session, _ = case.make(peer)
            original = peer.sendall
            def send(data):
                original(data)
                if data == case.cfg.ap_password + '\n':
                    time.sleep(.6)  # Host pause, not a simulated network delay.
            with patch.object(peer, 'sendall', side_effect=send):
                try:
                    session.connect('192.0.2.11')
                except transport.TransportError as exc:
                    self.fail(f'Unit fixture confused a host pause with device timeout: {exc.code}')
            self.assertEqual(case.cfg.timeout, .5)
            self.assertIn('192.0.2.55', session.execute('show config wips summary'))
            self.assertEqual(peer.sent.count(case.cfg.ap_password + '\n'), 1)
            session.close()

    def test_host_pause_does_not_hide_explicit_ap_authentication_failure(self):
        # Break caught: the intended AUTH_FAILED check is bypassed by wall time
        # expiring during the fixture, so it tests a different error condition.
        with fixture() as case:
            peer = case.peer(**{case.cfg.ap_password + '\n': [b'Permission denied']})
            session, _ = case.make(peer)
            original = peer.sendall
            def send(data):
                original(data)
                if data == case.cfg.ap_password + '\n':
                    time.sleep(.6)
            with patch.object(peer, 'sendall', side_effect=send):
                with self.assertRaises(transport.TransportError) as caught:
                    session.connect('192.0.2.11')
            self.assertEqual(caught.exception.code, 'AP_AUTH_FAILED')
            self.assertFalse(caught.exception.retryable)
            self.assertTrue(peer.closed)
            self.assertFalse(any(command.startswith('config ') for command in peer.sent))

    def test_scripted_late_reply_still_expires_and_closes_connection(self):
        # Break caught: a timing fix ignores actual scripted delays or disables
        # Session's deadline instead of isolating host scheduling time.
        with fixture() as case:
            peer = case.peer(**{case.cfg.ap_password + '\n': [(0.8, b'waiting\r\n'), b'AP_11#']})
            session, _ = case.make(peer)
            with self.assertRaises(transport.TransportError) as caught:
                session.connect('192.0.2.11')
            self.assertEqual(caught.exception.code, 'AP_LOGIN_TIMEOUT')
            self.assertTrue(caught.exception.retryable)
            self.assertTrue(peer.closed)
            self.assertNotIn('show config wips summary\n', peer.sent)

    def test_clock_override_does_not_affect_global_time_or_next_fixture(self):
        # Break caught: patching time.monotonic globally contaminates unrelated
        # GUI/socket tests or leaving the fixture patch alive after cleanup.
        original_module = transport.time
        original_monotonic = time.monotonic
        with fixture() as case:
            self.assertIs(time.monotonic, original_monotonic)
            before = transport.time.monotonic()
            time.sleep(.02)
            self.assertEqual(transport.time.monotonic(), before,
                             'Synthetic time must move only when the fixture advances it')
            self.assertIs(time.monotonic, original_monotonic)
        self.assertIs(transport.time, original_module)
        with fixture() as case:
            self.assertEqual(transport.time.monotonic(), before,
                             'A new test gets an independent, fresh clock')

    def test_prompt_settle_interval_is_not_bypassed(self):
        # Break caught: replacing the clock by zeroing the prompt settle guard.
        with fixture() as case:
            peer = case.peer()
            session, _ = case.make(peer)
            original = peer.recv
            arrived = []
            def receive(count):
                value = original(count)
                if value == b'#\x1b[0m':
                    arrived.append(transport.time.monotonic())
                return value
            with patch.object(peer, 'recv', side_effect=receive):
                session.connect('192.0.2.11')
            self.assertEqual(len(arrived), 1)
            self.assertGreaterEqual(transport.time.monotonic() - arrived[0], .08)
            session.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
