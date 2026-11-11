"""Small bounded Telnet/NVT adapter using only the Python standard library.

Only interactive terminal features required by WEC8500 are negotiated.
Telnet credentials and traffic are plaintext on the controller connection.
"""
from __future__ import annotations

import select
import socket
import threading

IAC, WILL, WONT, DO, DONT, SB, SE = 255, 251, 252, 253, 254, 250, 240
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31
_MAX_BUFFER = 1024 * 1024
_MAX_SUBNEG = 4096


class TelnetProtocolError(OSError):
    """Invalid or oversized terminal protocol data, not a transient network error."""


class TelnetChannel:
    def __init__(self, sock: socket.socket, timeout: float, stop: threading.Event):
        self._socket = sock
        self._stop = stop
        self._closed = False
        self._buffer = bytearray()
        self._state = "data"
        self._neg_command = None
        self._subneg = bytearray()
        self._remote_options = set()
        self._local_options = set()
        self._after_cr = False
        self._observer = None
        self.settimeout(timeout)

    def set_observer(self, callback):
        self._observer = callback

    def _activity(self):
        if self._observer is not None:
            try:
                self._observer('activity', {})
            except Exception:
                pass  # Diagnostic consumers must not interrupt device operations.

    @classmethod
    def connect(cls, host: str, port: int, timeout: float, stop: threading.Event):
        if stop.is_set():
            raise OSError("Connection cancelled")
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            if stop.is_set():
                raise OSError("Connection cancelled")
            return cls(sock, timeout, stop)
        except Exception:
            sock.close()
            raise

    @property
    def closed(self):
        return self._closed

    def settimeout(self, timeout):
        self._socket.settimeout(timeout)

    def _check(self):
        if self._stop.is_set():
            raise OSError("Connection cancelled")
        if self._closed:
            raise OSError("Connection closed")

    def _send_control(self, data: bytes):
        self._check()
        self._socket.sendall(data)

    def sendall(self, data: str | bytes):
        self._check()
        if isinstance(data, str):
            data = data.encode("utf-8")
        # NVT newline is CR LF; literal CR is CR NUL; literal IAC is doubled.
        data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\r\x00").replace(b"\n", b"\r\n")
        self._socket.sendall(data.replace(b"\xff", b"\xff\xff"))

    def _option(self, command: int, option: int):
        if command == WILL:
            if option in (ECHO, SGA):
                if option not in self._remote_options:
                    self._remote_options.add(option)
                    self._send_control(bytes((IAC, DO, option)))
            else:
                self._send_control(bytes((IAC, DONT, option)))
        elif command == WONT:
            if option in self._remote_options:
                self._remote_options.discard(option)
                self._send_control(bytes((IAC, DONT, option)))
        elif command == DO:
            if option in (SGA, TTYPE, NAWS):
                if option not in self._local_options:
                    self._local_options.add(option)
                    self._send_control(bytes((IAC, WILL, option)))
                    if option == NAWS:
                        self._send_control(bytes((IAC, SB, NAWS, 0, 240, 3, 232, IAC, SE)))
            else:
                self._send_control(bytes((IAC, WONT, option)))
        elif command == DONT:
            if option in self._local_options:
                self._local_options.discard(option)
                self._send_control(bytes((IAC, WONT, option)))

    def _finish_subneg(self):
        if self._subneg == bytes((TTYPE, 1)) and TTYPE in self._local_options:
            self._send_control(bytes((IAC, SB, TTYPE, 0)) + b"vt100" + bytes((IAC, SE)))
        self._subneg.clear()

    def _data_byte(self, value: int):
        if not (self._after_cr and value == 0):
            self._buffer.append(value)
        self._after_cr = value == 13
        if len(self._buffer) > _MAX_BUFFER:
            raise TelnetProtocolError("Telnet response exceeds size limit")

    def _feed(self, data: bytes):
        for value in data:
            if self._state == "data":
                if value == IAC:
                    self._state = "iac"
                else:
                    self._data_byte(value)
            elif self._state == "iac":
                if value == IAC:
                    self._data_byte(value)
                    self._state = "data"
                elif value in (WILL, WONT, DO, DONT):
                    self._neg_command = value
                    self._state = "option"
                elif value == SB:
                    self._subneg.clear()
                    self._state = "subneg"
                else:
                    self._state = "data"  # Ignore NOP/GA and other one-byte controls.
            elif self._state == "option":
                self._option(self._neg_command, value)
                self._state = "data"
            elif self._state == "subneg":
                if value == IAC:
                    self._state = "subneg_iac"
                else:
                    self._subneg.append(value)
            elif self._state == "subneg_iac":
                if value == SE:
                    self._finish_subneg()
                    self._state = "data"
                elif value == IAC:
                    self._subneg.append(IAC)
                    self._state = "subneg"
                else:
                    raise TelnetProtocolError("Malformed Telnet subnegotiation")
            if len(self._subneg) > _MAX_SUBNEG:
                raise TelnetProtocolError("Telnet subnegotiation exceeds size limit")

    def recv_ready(self):
        self._check()
        # Bound work per poll so cancellation and UI responsiveness are preserved.
        for _ in range(8):
            self._check()
            if not select.select([self._socket], [], [], 0)[0]:
                break
            data = self._socket.recv(32768)
            if not data:
                self.close()
                break
            self._activity()
            try:
                self._feed(data)
            except Exception:
                self.close()
                raise
        return bool(self._buffer) or self._closed

    def recv(self, count: int):
        if count <= 0:
            return b""
        if not self._buffer and not self._closed:
            self.recv_ready()
        result = bytes(self._buffer[:count])
        del self._buffer[:count]
        return result

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._socket.close()
