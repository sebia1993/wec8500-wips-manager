"""Local socket-pair checks for the small Telnet protocol adapter."""
import socket
import threading
import unittest


class TelnetChannelTests(unittest.TestCase):
    def pair(self):
        from wec_wips.telnet_channel import TelnetChannel
        left, right = socket.socketpair()
        right.settimeout(0.3)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        stop = threading.Event()
        return TelnetChannel(left, timeout=0.3, stop=stop), right, stop

    def test_module_exists(self):
        from importlib.util import find_spec
        self.assertIsNotNone(find_spec("wec_wips.telnet_channel"))

    def test_fragmented_iac_negotiation_does_not_reach_login_text(self):
        channel, server, _ = self.pair()
        for chunk in (b"User", b"\xff", b"\xfb", b"\x01", b"name:"):
            server.sendall(chunk)
            channel.recv_ready()
        self.assertEqual(channel.recv(99), b"Username:")
        self.assertEqual(server.recv(99), b"\xff\xfd\x01")

    def test_supported_and_unsupported_options(self):
        channel, server, _ = self.pair()
        server.sendall(b"\xff\xfb\x03\xff\xfb\x2a\xff\xfd\x2a\xff\xfd\x03")
        self.assertFalse(channel.recv_ready())
        self.assertEqual(server.recv(99), b"\xff\xfd\x03\xff\xfe\x2a\xff\xfc\x2a\xff\xfb\x03")

    def test_terminal_type_and_window_negotiation(self):
        channel, server, _ = self.pair()
        server.sendall(b"\xff\xfd\x18\xff\xfa\x18\x01\xff\xf0\xff\xfd\x1f")
        self.assertFalse(channel.recv_ready())
        self.assertEqual(server.recv(99), b"\xff\xfb\x18\xff\xfa\x18\x00vt100\xff\xf0\xff\xfb\x1f\xff\xfa\x1f\x00\xf0\x03\xe8\xff\xf0")

    def test_wont_acknowledges_active_remote_option_exactly_once(self):
        channel, server, _ = self.pair()
        server.sendall(b"\xff\xfb\x01")
        channel.recv_ready()
        self.assertEqual(server.recv(99), b"\xff\xfd\x01")
        # First WONT disables active ECHO; duplicate and inactive SGA need no reply.
        server.sendall(b"\xff\xfc\x01\xff\xfc\x01\xff\xfc\x03")
        channel.recv_ready()
        self.assertEqual(server.recv(99), b"\xff\xfe\x01")
        server.setblocking(False)
        with self.assertRaises(BlockingIOError):
            server.recv(99)

    def test_subnegotiation_and_escaped_iac_are_fragment_safe(self):
        channel, server, _ = self.pair()
        for chunk in (b"A\xff\xfa\x2aDATA", b"\xff", b"\xf0B\xff", b"\xffC"):
            server.sendall(chunk)
            channel.recv_ready()
        self.assertEqual(channel.recv(99), b"AB\xffC")

    def test_sendall_uses_crlf_and_escapes_iac(self):
        channel, server, _ = self.pair()
        channel.sendall("root\n")
        self.assertEqual(server.recv(99), b"root\r\n")
        channel.sendall(b"test\r\n\xff")
        self.assertEqual(server.recv(99), b"test\r\n\xff\xff")

    def test_cr_nul_padding_is_removed_even_between_reads(self):
        channel, server, _ = self.pair()
        server.sendall(b"A\r")
        self.assertTrue(channel.recv_ready())
        self.assertEqual(channel.recv(99), b"A\r")
        server.sendall(b"\x00B")
        self.assertTrue(channel.recv_ready())
        self.assertEqual(channel.recv(99), b"B")

    def test_closed_socket_and_stop_are_detected(self):
        channel, server, stop = self.pair()
        stop.set()
        with self.assertRaises(OSError):
            channel.recv_ready()
        stop.clear()
        server.close()
        channel.recv_ready()
        self.assertTrue(channel.closed)

    def test_subnegotiation_is_bounded(self):
        channel, server, _ = self.pair()
        server.sendall(b"\xff\xfa" + b"X" * 5000)
        with self.assertRaises(OSError):
            channel.recv_ready()

    def test_activity_observer_covers_negotiation_without_exposing_bytes(self):
        events = []
        channel, server, _ = self.pair()
        self.assertTrue(hasattr(channel, 'set_observer'))
        channel.set_observer(lambda kind, data: events.append((kind, data)))
        server.sendall(b"\xff\xfb\x03")
        self.assertFalse(channel.recv_ready())
        self.assertEqual(events, [('activity', {})])
        server.sendall(b'secret terminal data')
        self.assertTrue(channel.recv_ready())
        self.assertEqual(events, [('activity', {}), ('activity', {})])
        self.assertEqual(channel.recv(100), b'secret terminal data')

    def test_protocol_error_can_be_distinguished_from_network_error(self):
        from wec_wips import telnet_channel
        self.assertTrue(hasattr(telnet_channel, 'TelnetProtocolError'))
        channel, server, _ = self.pair()
        server.sendall(b"\xff\xfa" + b"X" * 5000)
        with self.assertRaises(telnet_channel.TelnetProtocolError):
            channel.recv_ready()


if __name__ == "__main__":
    unittest.main()
