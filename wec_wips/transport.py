"""Bounded WEC8500 TELNET login and nested AP SSH command transport.

The controller connection uses plaintext Telnet. Only a verified AP prompt
permits AP commands; terminal transcripts and credentials are never logged.
"""
from __future__ import annotations

import codecs
import ipaddress
import re
import threading
import time
from typing import Callable

from .telnet_channel import TelnetChannel, TelnetProtocolError


class TransportError(RuntimeError):
    """Safe diagnostic without terminal output or credentials."""

    def __init__(self, message, code='TRANSPORT_ERROR', retryable=False):
        super().__init__(message)
        self._code = code
        self._retryable = bool(retryable)

    @property
    def code(self):
        return self._code

    @property
    def retryable(self):
        return self._retryable


class Cancelled(TransportError):
    """The operator requested cancellation."""

    def __init__(self, message):
        super().__init__(message, code='CANCELLED', retryable=False)


_ANSI = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")
_PROMPT = re.compile(r"[A-Za-z0-9_().:/@~\-]{1,100}[#>]")
_LOGIN = re.compile(r"(?:username|user\s+name|login|id)\s*:\s*$", re.I)
_PASSWORD = re.compile(r"(?:password|passphrase)(?:[^\r\n:]{0,120})?:\s*$", re.I)
_QUESTION = re.compile(r"\(yes\s*(?:/|or)\s*no(?:/[^)\r\n]{0,80})?\)\s*[?:]?\s*$", re.I)
_HOST_TRUST_CONTEXT = re.compile(
    r"continue\s+connecting|authenticity\s+of\s+(?:the\s+)?host|"
    r"host\s+key|(?:key\s+)?fingerprint|"
    r"(?:add|save|store)[^\r\n]{0,120}known[ _-]hosts", re.I)
_UNRELATED_QUESTION = re.compile(r"\b(?:reset|reboot|delete|erase|format|factory|configuration)\b", re.I)
_CHANGED = re.compile(
    r"host identification has changed|host key verification failed|"
    r"host key[^\r\n]{0,200}(?:has changed|differs|mismatch)|dns spoofing", re.I)
_AUTH_FAIL = re.compile(r"permission denied|authentication (?:failed|failure)|access denied|login incorrect|incorrect password|invalid (?:username|user|password|login|credentials)", re.I)
_NETWORK_FAIL = re.compile(r"connection (?:refused|timed out|closed)|no route to host|network is unreachable|could not resolve hostname", re.I)
_MAX_BYTES = 1024 * 1024
_SETTLE_SECONDS = 0.08
_POLL_SECONDS = 0.01
_HOSTNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_GENERIC_NAMES = frozenset(('ap', 'root', 'admin', 'localhost', 'localhost.localdomain',
                            'busybox', 'unknown', 'none'))
_INVENTORY_HEADER = re.compile(
    r'^AP_ID\s+(?:Profile|CFG_NAME)\s+AP_NAME\s+MAC_Address\s+IPv4Addr(?:\s+.*)?$', re.I)
_INVENTORY_ROW = re.compile(
    r'^\d+\s+\S+\s+(\S+)\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\s+'
    r'(\d{1,3}(?:\.\d{1,3}){3})(?:\s+.*)?$')


def _safe_ap_hostname(value, secrets=()):
    if (not isinstance(value, str) or not _HOSTNAME.fullmatch(value)
            or value.lower() in _GENERIC_NAMES
            or any(isinstance(secret, str) and secret and secret in value for secret in secrets)):
        return ''
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return value
    return ''


def parse_ap_names(text, secrets=()):
    """Read only documented AP_NAME/IP table columns, never banner addresses."""
    names, seen_names, conflicts = {}, {}, set()
    in_table = False
    for line in _terminal_text(text).splitlines():
        line = line.strip()
        if _INVENTORY_HEADER.fullmatch(line):
            in_table = True
            continue
        if not in_table:
            continue
        match = _INVENTORY_ROW.fullmatch(line)
        if not match:
            continue
        name = _safe_ap_hostname(match.group(1), secrets)
        try:
            ip = ipaddress.IPv4Address(match.group(3))
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_multicast or int(ip) == 0xffffffff:
            continue
        address = str(ip)
        if address in conflicts:
            continue
        if address in seen_names and seen_names[address] != name:
            conflicts.add(address)
            names.pop(address, None)
            continue
        seen_names[address] = name
        if name:
            names[address] = name
    return names


def _terminal_text(value: str) -> str:
    value = _ANSI.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    # Backspaces can be emitted when paging or redrawing a prompt.
    while "\b" in value:
        updated = re.sub(r"[^\n]\x08|\x08", "", value)
        if updated == value:
            break
        value = updated
    return value.replace("\x00", "").replace("\x07", "")


def _last_prompt(text: str) -> str | None:
    last = text.rstrip().rsplit("\n", 1)[-1].strip()
    return last if _PROMPT.fullmatch(last) else None


class Session:
    """One controller connection containing at most one nested AP session."""

    def __init__(self, config, stop: threading.Event,
                 confirm: Callable[[str, str], bool]):
        self.config = config
        self.stop = stop
        self.confirm = confirm
        self._client = None
        self._channel = None
        self._controller_prompt = None
        self._ap_prompt = None
        self._ready = False
        self._controller_idle = False
        self._controller_attempted = False
        self._observer = None
        self._channel_observed = False
        self._ap_names = {}
        self._names_attempted = False
        self.ap_hostname = ''
        self.hostname_source = ''
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def set_observer(self, callback):
        """Observe static stage labels and byte activity, never terminal content."""
        self._observer = callback

    def _observe(self, kind, data):
        if self._observer is not None:
            try:
                self._observer(kind, data)
            except Exception:
                pass

    def _pending_text(self):
        """Discard only ASCII spacing already pending, never prompts or logs."""
        total = 0
        while self._channel is not None and not self._channel.closed:
            self._check_stop()
            if not self._channel.recv_ready():
                if self._decoder.getstate()[0]:
                    raise TransportError('완성되지 않은 터미널 데이터가 있어 다음 명령을 전송하지 않았습니다.',
                                         code='UNEXPECTED_DATA')
                return ''
            raw, _ = self._read_more('')
            total += len(raw)
            if total > _MAX_BYTES:
                raise TransportError('터미널 응답이 허용 크기를 초과했습니다.', code='PROTOCOL_ERROR')
            if raw.strip(' \t\r\n'):
                return raw
        raise TransportError('터미널 연결이 닫혔습니다.', code='CONNECTION_CLOSED', retryable=True)

    @property
    def controller_ready(self) -> bool:
        """True only after an exact return to the captured controller prompt."""
        if not (self._controller_idle and self._controller_prompt and not self._ap_prompt
                and not self._ready and self._client is not None and self._channel is not None
                and not self._channel.closed):
            return False
        try:
            if self._pending_text():
                self.close()
                return False
            return not self._channel.closed
        except (OSError, TransportError):
            self.close()
            return False

    def _check_stop(self):
        if self.stop.is_set():
            raise Cancelled("사용자가 작업을 중지했습니다.")

    def _complete_prompt(self, text):
        # A partial UTF-8 character after a prompt is still pending terminal data.
        return None if self._decoder.getstate()[0] else _last_prompt(text)

    def _validate_connection(self, ap_ip):
        try:
            ipaddress.IPv4Address(self.config.controller_ip)
            ipaddress.IPv4Address(ap_ip)
            if not 1 <= int(self.config.controller_port) <= 65535:
                raise ValueError
            if not 1 <= int(self.config.ap_port) <= 65535:
                raise ValueError
            if not 0 < float(self.config.timeout) <= 300:
                raise ValueError
            for username in (self.config.controller_user, self.config.ap_user):
                if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@\-]{0,63}", username):
                    raise ValueError
            for password in (self.config.controller_password, self.config.ap_password):
                if not password or len(password) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in password):
                    raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise TransportError("IP, 포트, 계정 또는 비밀번호 입력 형식을 확인하세요.", code='INVALID_INPUT') from None

    def connect(self, ap_ip: str):
        """Open the controller once, then enter an AP only from verified idle CLI."""
        if self._ap_prompt or self._ready:
            raise TransportError("현재 AP에서 exit 후 컨트롤러 복귀를 확인해야 다음 AP에 접속할 수 있습니다.", code='SESSION_NOT_READY')
        self.ap_hostname = ''
        self.hostname_source = ''
        try:
            self._check_stop()
            self._validate_connection(ap_ip)
            if self._client is None:
                if self._controller_attempted:
                    raise TransportError("컨트롤러 세션이 종료되었습니다. 이 작업에서는 자동 재접속하지 않습니다.", code='SESSION_NOT_READY')
                self._controller_attempted = True
                self._open_controller()
            if not self.controller_ready:
                raise TransportError("컨트롤러 프롬프트 복귀가 확인되지 않아 다음 AP 접속을 중지했습니다.", code='SESSION_NOT_READY')
            if ap_ip in self._ap_names:
                self.ap_hostname = self._ap_names[ap_ip]
                self.hostname_source = '컨트롤러 AP_NAME'
            self._controller_idle = False
            self._observe('stage', {'stage': 'AP 로그인'})
            self._send(f"ssh {ap_ip} {self.config.ap_user} {int(self.config.ap_port)}")
            self._ap_prompt = self._wait_ap_login(ap_ip)
            self._ready = True
            if not self.ap_hostname:
                self.ap_hostname = self._hostname_from_prompt(self._ap_prompt)
                self.hostname_source = 'AP 프롬프트' if self.ap_hostname else ''
        except (TransportError, Cancelled):
            self.close()
            raise
        except Exception as exc:
            self.close()
            if self.stop.is_set():
                raise Cancelled("사용자가 작업을 중지했습니다.") from None
            # Never expose a server response or low-level exception containing credentials.
            if isinstance(exc, TelnetProtocolError):
                raise TransportError('TELNET 응답 형식 또는 크기를 확인하지 못했습니다.', code='PROTOCOL_ERROR') from None
            if isinstance(exc, OSError):
                raise TransportError('터미널 통신 오류가 발생했습니다.', code='IO_ERROR', retryable=True) from None
            raise TransportError("컨트롤러 TELNET 연결에 실패했습니다. 주소·포트·통신 경로를 확인하세요.") from None

    def _open_controller(self):
        self._open_controller_login()
        if getattr(self.config, 'lookup_hostnames', False) and not self._names_attempted:
            self._names_attempted = True
            self._observe('stage', {'stage': 'AP 이름 조회'})
            self._check_stop()
            try:
                self._controller_idle = False
                self._send('show ap summary')
                output = self._wait_inventory()
                self._ap_names = parse_ap_names(output, self._identity_secrets())
                self._controller_idle = True
            except Cancelled:
                raise
            except (TransportError, OSError) as exc:
                # A name lookup is optional, but its uncertain CLI cannot be reused.
                # Re-authenticate once without repeating the optional command.
                if (isinstance(exc, TransportError) and not exc.retryable
                        or isinstance(exc, TelnetProtocolError)):
                    raise
                self.close()
                self._check_stop()
                self._open_controller_login()

    def _identity_secrets(self):
        return tuple(getattr(self.config, name, '') for name in
                     ('controller_password', 'ap_password', 'shared_key'))

    def _hostname_from_prompt(self, prompt):
        if not prompt or prompt == self._controller_prompt:
            return ''
        plain = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]{0,127})[#>]', prompt)
        shell = re.fullmatch(r'[A-Za-z0-9_.-]+@([A-Za-z0-9][A-Za-z0-9_.-]{0,127})(?::[A-Za-z0-9_./~\-]*)?[#>]', prompt)
        match = shell or plain
        return _safe_ap_hostname(match.group(1), self._identity_secrets()) if match else ''

    def _wait_inventory(self):
        deadline = time.monotonic() + float(self.config.timeout)
        raw = ''
        changed = time.monotonic()
        while time.monotonic() < deadline:
            raw, new = self._read_more(raw)
            if new:
                changed = time.monotonic()
            text = _terminal_text(raw)
            if (_LOGIN.search(text) or _PASSWORD.search(text)) and not self._decoder.getstate()[0]:
                raise TransportError('AP 이름 조회 중 컨트롤러 인증 상태가 변경되었습니다.',
                                     code='CONTROLLER_AUTH_FAILED')
            if (self._complete_prompt(text) == self._controller_prompt
                    and time.monotonic() - changed >= _SETTLE_SECONDS):
                return text.rstrip()[:-len(self._controller_prompt)].rstrip()
            if self.stop.wait(_POLL_SECONDS):
                self._check_stop()
        raise TransportError('AP 이름 조회 응답 확인 시간이 초과되었습니다.',
                             code='COMMAND_TIMEOUT', retryable=True)

    def _open_controller_login(self):
        self._decoder.reset()
        self._observe('stage', {'stage': '컨트롤러 연결'})
        try:
            self._channel = TelnetChannel.connect(
                host=self.config.controller_ip, port=int(self.config.controller_port),
                timeout=float(self.config.timeout), stop=self.stop,
            )
        except TimeoutError:
            self._check_stop()
            raise TransportError('컨트롤러 TELNET 연결 시간이 초과되었습니다.',
                                 code='CONTROLLER_CONNECT_TIMEOUT', retryable=True) from None
        except OSError:
            self._check_stop()
            raise TransportError('컨트롤러 TELNET 연결에 실패했습니다. 주소·포트·통신 경로를 확인하세요.',
                                 code='CONTROLLER_CONNECT_FAILED', retryable=True) from None
        self._client = self._channel
        self._channel_observed = hasattr(self._channel, 'set_observer')
        if self._channel_observed:
            self._channel.set_observer(self._observe)
        self._observe('stage', {'stage': '컨트롤러 로그인'})
        self._controller_prompt = self._wait_controller_login()
        self._controller_idle = True

    def _wait_controller_login(self):
        deadline = time.monotonic() + float(self.config.timeout)
        raw = ""
        changed = time.monotonic()
        username_sent = False
        password_sent = False
        while time.monotonic() < deadline:
            raw, new = self._read_more(raw)
            if new:
                changed = time.monotonic()
            text = _terminal_text(raw)
            if _AUTH_FAIL.search(text):
                raise TransportError("컨트롤러 TELNET 인증에 실패했습니다. 자동 재시도하지 않습니다.", code='CONTROLLER_AUTH_FAILED')
            if _LOGIN.search(text) and not self._decoder.getstate()[0]:
                if username_sent:
                    raise TransportError("컨트롤러 TELNET ID 입력 요청이 반복되어 중지했습니다.", code='CONTROLLER_AUTH_FAILED')
                self._send(self.config.controller_user)
                username_sent = True
                raw = ""
                changed = time.monotonic()
                continue
            if _PASSWORD.search(text) and not self._decoder.getstate()[0]:
                if not username_sent or password_sent:
                    raise TransportError("컨트롤러 TELNET 비밀번호 입력 순서를 확인하지 못했습니다.", code='CONTROLLER_AUTH_FAILED')
                self._send(self.config.controller_password)
                password_sent = True
                raw = ""
                changed = time.monotonic()
                continue
            prompt = self._complete_prompt(text)
            if prompt and prompt != self.config.controller_password and time.monotonic() - changed >= _SETTLE_SECONDS:
                if not username_sent or not password_sent:
                    raise TransportError("컨트롤러 TELNET 로그인이 확인되지 않아 AP 접속을 중단했습니다.", code='CONTROLLER_AUTH_FAILED')
                return prompt
            if self.stop.wait(_POLL_SECONDS):
                self._check_stop()
        raise TransportError("컨트롤러 TELNET 로그인 또는 CLI 프롬프트 확인 시간이 초과되었습니다.",
                             code='CONTROLLER_LOGIN_TIMEOUT', retryable=True)

    def _send(self, text: str):
        self._check_stop()
        if self._channel is None or self._channel.closed:
            raise TransportError("터미널 연결이 닫혔습니다.", code='CONNECTION_CLOSED', retryable=True)
        self._channel.sendall(text + "\n")

    def _read_more(self, accumulated: str) -> tuple[str, bool]:
        self._check_stop()
        if self._channel is None or self._channel.closed:
            raise TransportError("터미널 연결이 닫혔습니다.", code='CONNECTION_CLOSED', retryable=True)
        if not self._channel.recv_ready():
            return accumulated, False
        chunk = self._channel.recv(32768)
        if not chunk:
            raise TransportError("터미널 연결이 종료되었습니다.", code='CONNECTION_CLOSED', retryable=True)
        if not self._channel_observed:
            self._observe('activity', {})
        accumulated += self._decoder.decode(chunk, final=False)
        if len(accumulated) > _MAX_BYTES:
            raise TransportError("터미널 응답이 허용 크기를 초과했습니다.", code='PROTOCOL_ERROR')
        return accumulated, True

    def _wait_controller_prompt(self, expected: str | None = None):
        deadline = time.monotonic() + float(self.config.timeout)
        raw = ""
        changed = time.monotonic()
        while time.monotonic() < deadline:
            raw, new = self._read_more(raw)
            if new:
                changed = time.monotonic()
            text = _terminal_text(raw)
            prompt = self._complete_prompt(text)
            if prompt and prompt != self.config.controller_password and time.monotonic() - changed >= _SETTLE_SECONDS:
                if expected is None or prompt == expected:
                    return prompt
            if self.stop.wait(_POLL_SECONDS):
                self._check_stop()
        raise TransportError("컨트롤러 TELNET CLI 프롬프트 복귀를 확인하지 못했습니다.",
                             code='RETURN_TIMEOUT', retryable=True)

    def _wait_ap_login(self, ap_ip):
        deadline = time.monotonic() + float(self.config.timeout)
        raw = ""
        changed = time.monotonic()
        password_sent = False
        trust_answered = False
        while time.monotonic() < deadline:
            raw, new = self._read_more(raw)
            if new:
                changed = time.monotonic()
            text = _terminal_text(raw)
            if _CHANGED.search(text):
                raise TransportError("AP 호스트 키 검증에 실패했습니다. 컨트롤러의 SSH 호스트 키를 확인하세요.", code='HOST_KEY_CHANGED')
            if _AUTH_FAIL.search(text):
                raise TransportError("AP SSH 인증에 실패했습니다. 자동 재시도하지 않습니다.", code='AP_AUTH_FAILED')
            if _NETWORK_FAIL.search(text):
                raise TransportError("컨트롤러에서 AP SSH 연결에 실패했습니다. AP 주소·포트·경로를 확인하세요.",
                                     code='AP_CONNECT_FAILED', retryable=True)
            if _QUESTION.search(text) and not self._decoder.getstate()[0]:
                if trust_answered:
                    raise TransportError("AP 호스트 키 확인이 반복되어 중지했습니다.", code='HOST_KEY_REJECTED')
                question_line = text.rstrip().rsplit("\n", 1)[-1]
                if _UNRELATED_QUESTION.search(question_line) or not _HOST_TRUST_CONTEXT.search(text[-2048:]):
                    raise TransportError("SSH 호스트 키 확인으로 식별되지 않은 질문이 있어 응답하지 않고 연결을 중지했습니다.", code='UNEXPECTED_DATA')
                if not getattr(self.config, "auto_accept_ap_host_key", True):
                    fingerprint = re.search(r"SHA256:[A-Za-z0-9+/=]+|(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}", text)
                    if not fingerprint:
                        raise TransportError("AP 호스트 키 지문을 읽지 못해 연결을 중지했습니다.", code='HOST_KEY_REJECTED')
                    accepted = self.confirm(
                        "AP SSH 호스트 키 확인",
                        f"대상: {ap_ip}:{self.config.ap_port}\n지문: {fingerprint.group(0)}\n\n"
                        "관리자가 확인한 장비의 지문과 일치할 때만 승인하세요.\n"
                        "승인 응답은 WEC8500의 SSH 클라이언트에 전달됩니다.",
                    )
                    self._check_stop()
                    if not accepted:
                        raise TransportError("AP 호스트 키 승인이 거절되었습니다.", code='HOST_KEY_REJECTED')
                self._send("yes")
                trust_answered = True
                raw = ""
                changed = time.monotonic()
                deadline = changed + float(self.config.timeout)
                continue
            if _PASSWORD.search(text) and not self._decoder.getstate()[0]:
                if password_sent:
                    raise TransportError("AP 비밀번호 인증이 반복되어 중지했습니다.", code='AP_AUTH_FAILED')
                self._send(self.config.ap_password)
                password_sent = True
                raw = ""
                changed = time.monotonic()
                continue
            prompt = self._complete_prompt(text)
            if prompt and time.monotonic() - changed >= _SETTLE_SECONDS:
                if prompt == self._controller_prompt:
                    raise TransportError("AP에 연결되지 않고 컨트롤러 프롬프트로 돌아왔습니다.", code='SESSION_NOT_READY')
                if prompt not in (self.config.ap_password, self.config.controller_password):
                    return prompt
            if self.stop.wait(_POLL_SECONDS):
                self._check_stop()
        raise TransportError("AP SSH 로그인 또는 프롬프트 확인 시간이 초과되었습니다.",
                             code='AP_LOGIN_TIMEOUT', retryable=True)

    def execute(self, command: str) -> str:
        """Return complete AP output; never retry a command, including on timeout."""
        if not self._ready or not self._ap_prompt:
            raise TransportError("검증된 AP SSH 세션이 없습니다.", code='SESSION_NOT_READY')
        if not command or len(command) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in command):
            raise TransportError("명령어에 허용되지 않은 제어문자가 있습니다.", code='INVALID_INPUT')
        try:
            # Fail closed if an unsolicited disconnect was received between commands.
            raw = self._pending_text()
            if raw:
                if _CHANGED.search(_terminal_text(raw)):
                    raise TransportError('AP 호스트 키 검증에 실패했습니다. 컨트롤러의 SSH 호스트 키를 확인하세요.', code='HOST_KEY_CHANGED')
                if _last_prompt(_terminal_text(raw)) == self._controller_prompt:
                    raise TransportError("AP 세션이 종료되어 다음 명령을 전송하지 않았습니다.", code='UNEXPECTED_DATA')
                raise TransportError("예상하지 못한 SSH 데이터가 있어 다음 명령을 전송하지 않았습니다.", code='UNEXPECTED_DATA')
            self._send(command)
            return self._wait_command()
        except (TransportError, Cancelled):
            self.close()
            raise
        except Exception as exc:
            self.close()
            if self.stop.is_set():
                raise Cancelled('사용자가 작업을 중지했습니다.') from None
            if isinstance(exc, TelnetProtocolError):
                raise TransportError('TELNET 응답 형식 또는 크기를 확인하지 못했습니다.', code='PROTOCOL_ERROR') from None
            if isinstance(exc, OSError):
                raise TransportError('SSH 명령 처리 중 통신 오류가 발생했습니다. 적용 여부는 재조회가 필요합니다.',
                                     code='IO_ERROR', retryable=True) from None
            raise TransportError("SSH 명령 처리 중 통신 오류가 발생했습니다. 적용 여부는 재조회가 필요합니다.") from None

    def leave_ap(self):
        """Send one exit and require the original controller prompt before reuse."""
        try:
            if not self._ready or not self._ap_prompt or not self._controller_prompt:
                raise TransportError("종료할 AP SSH 세션이 확인되지 않았습니다.", code='SESSION_NOT_READY')
            if self._pending_text():
                raise TransportError("AP 종료 전 세션 상태가 달라져 컨트롤러 연결을 종료했습니다.", code='UNEXPECTED_DATA')
            self._ready = False
            self._controller_idle = False
            self._observe('stage', {'stage': '컨트롤러 복귀'})
            self._send("exit")
            self._wait_controller_prompt(expected=self._controller_prompt)
            self._ap_prompt = None
            self._controller_idle = True
        except (TransportError, Cancelled):
            self.close()
            raise
        except Exception as exc:
            self.close()
            if self.stop.is_set():
                raise Cancelled('사용자가 작업을 중지했습니다.') from None
            if isinstance(exc, TelnetProtocolError):
                raise TransportError('TELNET 응답 형식 또는 크기를 확인하지 못했습니다.', code='PROTOCOL_ERROR') from None
            if isinstance(exc, OSError):
                raise TransportError('AP 종료 중 통신 오류가 발생했습니다.', code='IO_ERROR', retryable=True) from None
            raise TransportError("AP 종료 후 컨트롤러 복귀를 확인하지 못했습니다. 다음 AP 작업을 중단합니다.") from None

    def _wait_command(self):
        deadline = time.monotonic() + float(self.config.timeout)
        raw = ""
        changed = time.monotonic()
        while time.monotonic() < deadline:
            raw, new = self._read_more(raw)
            if new:
                changed = time.monotonic()
            text = _terminal_text(raw)
            prompt = self._complete_prompt(text)
            if prompt == self._controller_prompt:
                raise TransportError("AP 세션이 끊겨 컨트롤러로 돌아왔습니다. 적용 여부는 재조회가 필요합니다.",
                                     code='CONNECTION_CLOSED', retryable=True)
            if prompt == self._ap_prompt and time.monotonic() - changed >= _SETTLE_SECONDS:
                # Keep the body (including command echo) for the strict summary parser.
                return text.rstrip()[:-len(self._ap_prompt)].rstrip()
            if self.stop.wait(_POLL_SECONDS):
                self._check_stop()
        raise TransportError("AP 응답 확인 시간이 초과되었습니다. 적용 여부는 재조회가 필요합니다.",
                             code='COMMAND_TIMEOUT', retryable=True)

    def close(self):
        self._decoder.reset()
        self._controller_idle = False
        self._ready = False
        self._ap_prompt = None
        self._controller_prompt = None
        channel, client = self._channel, self._client
        self._channel = self._client = None
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        if client is not None and client is not channel:
            try:
                client.close()
            except Exception:
                pass
