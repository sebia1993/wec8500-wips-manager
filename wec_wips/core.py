"""Input validation, WIPS configuration verification and sequential jobs.

Only explicitly allowlisted result fields leave this module. Terminal replies
are never exported. Operator summaries may retain the explicitly requested
device-returned shared key; the diagnostic summary helper masks it by default.
"""
from __future__ import annotations

import csv
import ipaddress
import math
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from pathlib import Path
from typing import Callable

SUMMARY_COMMAND = 'show config wips summary'
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
KEY_PATTERN = re.compile(r'[A-Za-z0-9!@#%^*+=_.,:/\-\[\]]{1,256}\Z')
USER_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\Z')
GOOD_STATUSES = {'조회완료', '변경확인', '이미일치', 'IP일치', 'IP불일치'}
HOSTNAME_PATTERN = re.compile(r'[A-Za-z0-9가-힣][A-Za-z0-9가-힣_. -]{0,127}\Z')


def safe_hostname(value, secrets=()) -> str:
    """Accept a local/display name without controls or credential substrings."""
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return ''
    value = value.strip()
    if not HOSTNAME_PATTERN.fullmatch(value):
        return ''
    if any(isinstance(secret, str) and secret and secret in value for secret in secrets):
        return ''
    return value


def _ipv4(value: str, purpose: str, target: bool = True) -> str:
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except (ValueError, AttributeError):
        raise ValueError(f'{purpose}: 올바른 IPv4 주소를 입력하세요.') from None
    if target and (ip.is_unspecified or ip.is_multicast or int(ip) == 0xffffffff):
        raise ValueError(f'{purpose}: 접속 또는 변경 대상으로 사용할 수 없는 주소입니다.')
    return str(ip)


def parse_ap_ips(text: str) -> list[str]:
    tokens = re.split(r'[\s,;]+', text.strip()) if text.strip() else []
    if not tokens:
        raise ValueError('작업할 AP IP를 하나 이상 입력하세요.')
    if len(tokens) > 10000:
        raise ValueError('한 번에 입력할 수 있는 AP는 최대 10,000개입니다.')
    return list(dict.fromkeys(_ipv4(t, 'AP IP') for t in tokens))


@dataclass
class RunConfig:
    controller_ip: str
    controller_port: int
    controller_user: str
    controller_password: str = field(repr=False)
    ap_ips: list[str]
    ap_port: int
    ap_user: str
    ap_password: str = field(repr=False)
    server_ip: str = ''
    shared_key: str = field(default='', repr=False)
    syntax: str = 'with_nat'
    nat_mode: str = 'keep'
    timeout: float = 20
    demo: bool = False
    stop_on_error: bool = True
    auto_accept_ap_host_key: bool = True
    auto_recover: bool = True
    max_retries: int = 2
    retry_delays: tuple[float, float] = (3.0, 10.0)
    lookup_hostnames: bool = False
    ap_hostnames: dict[str, str] = field(default_factory=dict)

    def validate(self, mode: str) -> None:
        if mode not in ('inspect', 'apply', 'verify_ip'):
            raise ValueError('지원하지 않는 작업입니다.')
        self.controller_ip = _ipv4(self.controller_ip, '컨트롤러 IP')
        self.ap_ips = parse_ap_ips('\n'.join(self.ap_ips))
        if self.controller_ip in self.ap_ips:
            raise ValueError('컨트롤러 IP를 AP 작업 대상에 넣을 수 없습니다.')
        if type(self.lookup_hostnames) is not bool or not isinstance(self.ap_hostnames, dict):
            raise ValueError('AP 이름 조회 설정 또는 IP·호스트명 목록 형식을 확인하세요.')
        normalized_names = {}
        for address, hostname in self.ap_hostnames.items():
            address = _ipv4(address, '호스트명 목록의 AP IP')
            clean_name = safe_hostname(hostname)
            if address not in self.ap_ips or address in normalized_names or not clean_name:
                raise ValueError('호스트명은 대상 AP IP와 연결하고, 1~128자 영문·숫자·한글·공백·_ . -만 사용하세요.')
            normalized_names[address] = clean_name
        self.ap_hostnames = normalized_names
        for port in (self.controller_port, self.ap_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('Telnet·SSH 포트는 1~65535 정수여야 합니다.')
        if not isinstance(self.timeout, (int, float)) or not math.isfinite(self.timeout) or not 2 <= self.timeout <= 120:
            raise ValueError('대기시간은 2~120초로 지정하세요.')
        if type(self.auto_recover) is not bool or type(self.max_retries) is not int or not 0 <= self.max_retries <= 2:
            raise ValueError('자동 복구 설정 또는 재시도 횟수(0~2)를 확인하세요.')
        if (not isinstance(self.retry_delays, (tuple, list)) or len(self.retry_delays) != 2
                or any(type(delay) not in (int, float) or not math.isfinite(delay) or not 0 <= delay <= 30
                       for delay in self.retry_delays)):
            raise ValueError('재접속 대기시간은 0~30초 숫자 두 개여야 합니다.')
        if mode != 'verify_ip':
            if self.syntax not in ('with_nat', 'without_nat') or self.nat_mode not in ('keep','1','2'):
                raise ValueError('명령 문법 또는 NAT 모드를 확인하세요.')
            if self.syntax == 'without_nat' and self.nat_mode != 'keep':
                raise ValueError('NAT 없는 문법에서는 NAT 모드를 기존 값 유지로 선택하세요.')
        if not self.demo:
            for user in (self.controller_user, self.ap_user):
                if not USER_PATTERN.fullmatch(user):
                    raise ValueError('ID는 영문·숫자·밑줄로 시작하며 영문·숫자와 _ . @ - 조합으로 1~64자 입력하세요.')
            for password in (self.controller_password, self.ap_password):
                if not password or len(password) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in password):
                    raise ValueError('비밀번호를 입력하세요. 줄바꿈·제어문자는 사용할 수 없습니다.')
        if mode in ('apply', 'verify_ip'):
            self.server_ip = _ipv4(self.server_ip, 'WIPS 서버 IP')
        if mode == 'apply':
            if not KEY_PATTERN.fullmatch(self.shared_key):
                raise ValueError('키는 공백 없이 1~256자 입력하세요. 지원 문자: 영문·숫자 ! @ # % ^ * + = _ . , : / - [ ]')


@dataclass
class Summary:
    server_ip: str
    nat: str | None = None
    shared_key: str | None = field(default=None, repr=False)
    mode: str = ''


def parse_summary(text: str) -> Summary:
    """Parse named fields only: never match an IP from a command echo/banner."""
    clean = ANSI.sub('', text).replace('\r', '')
    names = {'server_ip': r'wips[ \t]+server[ \t]+ip', 'nat': r'wips[ \t]+nat',
             'shared_key': r'wips[ \t]+sharedkey', 'mode': r'wips[ \t]+mode'}
    parsed = {}
    for name, label in names.items():
        # A blank field must never consume the next line as its value.
        matches = re.findall(r'^[ \t]*' + label
                             + r'(?:[ \t]*[:=][ \t]*|[ \t]+\.{2,}[ \t]*|[ \t]+)(.*?)[ \t]*$',
                             clean, re.I | re.M)
        if len(matches) > 1:
            raise ValueError('조회 결과에 중복 항목이 있어 해석할 수 없습니다.')
        if matches:
            parsed[name] = matches[0].strip()
    if not parsed.get('server_ip'):
        raise ValueError('조회 결과에서 WIPS 서버 IP 항목을 찾을 수 없습니다.')
    server = _ipv4(parsed['server_ip'], '조회된 서버 IP', target=False)
    nat = parsed.get('nat')
    if nat is not None and nat not in ('1', '2'):
        raise ValueError('조회된 NAT 값이 지원 형식(1 또는 2)이 아닙니다.')
    key = parsed.get('shared_key')
    if not key or re.fullmatch(r'[\*•]+', key) or key.lower() in (
            '<hidden>', '<masked>', 'hidden', 'masked', '[hidden]', '[masked]', '[unavailable]'):
        key = None
    return Summary(server, nat, key, parsed.get('mode', ''))


def parse_server_ip(text: str) -> str:
    """Read only the exact WIPS server IP field; ignore all NAT/key fields."""
    clean = ANSI.sub('', text).replace('\r', '')
    matches = re.findall(
        r'^[ \t]*wips[ \t]+server[ \t]+ip'
        r'(?:[ \t]*[:=][ \t]*|[ \t]+\.{2,}[ \t]*|[ \t]+)(.*?)[ \t]*$',
        clean, re.I | re.M,
    )
    if len(matches) != 1 or not matches[0].strip():
        raise ValueError('조회 결과에서 단일 WIPS 서버 IP 항목을 확인할 수 없습니다.')
    return _ipv4(matches[0], '조회된 서버 IP', target=False)


_SUMMARY_NOTE = '※ 인식한 조회 항목만 표시합니다. 공유키·원문·미인식 항목은 저장하지 않습니다.'
_SUMMARY_REVEALED_NOTE = ('※ 인식한 조회 항목만 표시합니다. 공유키는 장비가 반환한 값이며 '
                          '장비가 숨긴 값은 복원하지 않습니다. 원문·미인식 항목은 제외합니다.')


def _safe_summary_fields(text: str, secrets=(), *, reveal_shared_key=False) -> dict[str, str]:
    """Read displayable values only; never retain raw replies or unknown fields."""
    clean = ANSI.sub('', text).replace('\r', '')
    found = {}
    labels = {'mode': r'wips[ \t]+mode', 'server_ip': r'wips[ \t]+server[ \t]+ip',
              'nat': r'wips[ \t]+nat', 'shared_key': r'wips[ \t]+sharedkey'}
    for name, label in labels.items():
        found[name] = re.findall(r'^[ \t]*' + label
                                + r'(?:[ \t]*[:=][ \t]*|[ \t]+\.{2,}[ \t]*|[ \t]+)(.*?)[ \t]*$',
                                clean, re.I | re.M)
    safe = {}
    if len(found['server_ip']) == 1:
        try:
            safe['server_ip'] = _ipv4(found['server_ip'][0], '조회된 서버 IP', target=False)
        except ValueError:
            pass
    if len(found['nat']) == 1 and found['nat'][0] in ('1', '2'):
        safe['nat'] = found['nat'][0]
    # A password or old/new key echoed into an otherwise plausible mode label
    # must not become a new route for exporting credentials.
    protected = [value for value in (*secrets, *found['shared_key'])
                 if isinstance(value, str) and value and value != '[MASKED]']
    if len(found['mode']) == 1:
        mode = found['mode'][0]
        if (re.fullmatch(r'WIPS_[A-Z0-9_]{1,48}_MODE', mode)
                and not any(secret in mode for secret in protected)):
            safe['mode'] = mode
    if found['shared_key']:
        if not reveal_shared_key:
            safe['shared_key'] = '[MASKED]'
        else:
            # Match the original field line: removing embedded ANSI/control bytes
            # could silently reconstruct a key different from the returned value.
            raw_keys = re.findall(
                r'^[ \t]*wips[ \t]+sharedkey'
                r'(?:[ \t]*[:=][ \t]*|[ \t]+\.{2,}[ \t]*|[ \t]+)(.*)$',
                text.replace('\r\n', '\n'), re.I | re.M,
            )
            key = raw_keys[0] if len(raw_keys) == len(found['shared_key']) == 1 else ''
            safe['shared_key'] = (key if 1 <= len(key) <= 256 and key.isprintable()
                                  else '[UNAVAILABLE]')
    return safe


def safe_summary_text(text: str, secrets=(), *, reveal_shared_key=False) -> str:
    """Normalized named-field summary for local reports, not a terminal transcript."""
    values = _safe_summary_fields(text, secrets, reveal_shared_key=reveal_shared_key)
    labels = (('mode', 'wips mode'), ('server_ip', 'wips server ip'),
              ('nat', 'wips nat'), ('shared_key', 'wips sharedkey'))
    lines = [f'{label} : {values[name]}' for name, label in labels if name in values]
    if not lines:
        lines.append('안전하게 표시할 조회 항목이 없습니다.')
    note = _SUMMARY_REVEALED_NOTE if reveal_shared_key else _SUMMARY_NOTE
    return '\n'.join([*lines, note])


def cli_error(text: str) -> bool:
    """Ignore echoes/field values; recognize only error-prefixed reply lines."""
    return bool(re.search(r'^\s*(?:%\s*)?(?:usage\s*:|invalid\b|unknown\s+command\b|'
                          r'error\b|failed\b|failure\b|syntax\s+error\b|'
                          r'permission\s+denied\b|not\s+supported\b|incomplete\s+command\b)',
                          ANSI.sub('', text), re.I | re.M))


@dataclass
class Result:
    time: str
    ap_ip: str
    status: str
    before_ip: str = ''
    after_ip: str = ''
    before_nat: str = ''
    after_nat: str = ''
    key_check: str = ''
    message: str = ''
    mode: str = ''
    simulated: bool = False
    controller_return: str = '미접속'
    target_ip: str = ''
    ip_check: str = ''
    attempts: int = 0
    error_code: str = ''
    stage: str = ''
    config_sent: bool = False
    expected_nat: str = ''
    duration_seconds: float = 0.0
    summary_before: str = field(default='', repr=False)
    summary_after: str = field(default='', repr=False)
    wips_mode: str = ''
    hostname: str = ''
    hostname_source: str = ''
    observed_at: str = ''


def _safe_cell(value) -> str:
    text = str(value)
    return "'" + text if text.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else text


def export_results(path: str | Path, results: list[Result]) -> None:
    names = [f.name for f in fields(Result)]
    target = Path(path)
    # Stage beside the destination: a failed write must not truncate a prior export.
    fd, name = tempfile.mkstemp(prefix='.wips-results-', suffix='.tmp', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8-sig', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=names)
            writer.writeheader()
            for result in results:
                writer.writerow({n: _safe_cell(getattr(result, n)) for n in names})
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


class DemoSession:
    """Network-free deterministic example; no socket access."""
    def __init__(self, config, stop, confirm):
        self.config, self.stop = config, stop
        self.ip, self.nat, self.key = '192.0.2.200', '1', 'DemoOldKey'
        self.controller_ready = False
        self.active = False
    def connect(self, ap_ip):
        if self.stop.is_set(): raise RuntimeError('stopped')
        if self.active: raise RuntimeError('AP must be exited before next connect')
        self.active, self.controller_ready = True, False
        self.ip, self.nat, self.key = '192.0.2.200', '1', 'DemoOldKey'
    def execute(self, command):
        if self.stop.is_set(): raise RuntimeError('stopped')
        if command == SUMMARY_COMMAND:
            return (f'wips mode ........ WIPS_SENSOR_MODE\n'
                    f'wips server ip ........ {self.ip}\n'
                    f'wips nat ........ {self.nat}\n'
                    f'wips sharedkey ........ {self.key}\nDEMO_AP#')
        args = command.split()
        self.ip = args[3]
        if len(args) == 6: self.nat, self.key = args[4], args[5]
        else: self.key = args[4]
        return 'DEMO_AP#'
    def leave_ap(self):
        if not self.active or self.stop.is_set(): raise RuntimeError('not at AP')
        self.active, self.controller_ready = False, True
    def close(self):
        self.active, self.controller_ready = False, False


class EventDeliveryError(RuntimeError):
    """A local event sink failed; never convert this into a device result."""


class Runner:
    def __init__(self, config: RunConfig, emit: Callable, confirm: Callable,
                 stop: threading.Event, session_factory=None, resume_results=None):
        self.config, self.emit, self.confirm, self.stop = config, emit, confirm, stop
        self.session_factory = session_factory
        self.resume_results = list(resume_results or [])
        self.results: list[Result] = []
        self._event_failed = False
        self._current_result: Result | None = None
        self._current_emitted = False

    def pending_results(self) -> list[Result]:
        """Copy completed and in-flight evidence after a worker exception."""
        # An early worker failure may happen before an AP is visited in this
        # run. Its previous possible-write evidence must survive every resume.
        by_ap = {result.ap_ip: replace(result) for result in self.resume_results
                 if isinstance(result, Result)}
        by_ap.update((result.ap_ip, replace(result)) for result in self.results)
        if self._current_result is not None:
            by_ap[self._current_result.ap_ip] = replace(self._current_result)
        return [by_ap[ap_ip] for ap_ip in self.config.ap_ips if ap_ip in by_ap]

    def _emit(self, kind, data):
        try:
            self.emit(kind, data)
        except Exception:
            self._event_failed = True
            self.stop.set()
            raise EventDeliveryError('작업 상태를 기록하거나 전달하지 못했습니다.') from None

    def _stage(self, result, stage):
        result.stage = stage
        self._emit('stage', {'ap_ip': result.ap_ip, 'stage': stage, 'attempt': result.attempts})

    def _observer(self, result, kind, data):
        if kind == 'stage':
            # Only application-authored stages, never terminal strings.
            stage = data.get('stage')
            if stage in ('컨트롤러 연결', '컨트롤러 로그인', 'AP 이름 조회', 'AP 로그인', '컨트롤러 복귀', 'exit'):
                self._stage(result, stage)
        elif kind == 'activity':
            self._emit('activity', {'ap_ip': result.ap_ip})

    @staticmethod
    def _close(session):
        if session is not None:
            try: session.close()
            except Exception: pass

    @staticmethod
    def _error_code(exc):
        from .transport import TransportError
        if isinstance(exc, TransportError):
            code = getattr(exc, 'code', 'TRANSPORT_ERROR')
            return code if isinstance(code, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) else 'TRANSPORT_ERROR'
        return 'INTERNAL_ERROR'

    def _resume_map(self, mode):
        prior = {}
        for result in self.resume_results:
            if (not isinstance(result, Result) or result.ap_ip not in self.config.ap_ips
                    or result.ap_ip in prior or result.mode != mode or result.simulated != self.config.demo
                    or result.expected_nat not in ('', '1', '2')
                    or type(result.attempts) is not int or result.attempts < 0):
                raise ValueError('이어하기 결과가 현재 작업과 일치하지 않습니다.')
            prior[result.ap_ip] = result
        return prior

    def run(self, mode: str = 'inspect') -> list[Result]:
        cfg = self.config
        cfg.validate(mode)
        previous = self._resume_map(mode)
        factory = self.session_factory
        if factory is None:
            if cfg.demo:
                factory = DemoSession
            else:
                from .transport import Session
                factory = Session
        self.results = []
        self._event_failed = False
        self._current_result = None
        self._current_emitted = False
        aborted = False
        session = None
        self._emit('log', {'message': '모의 실행: 실제 장비 접속 없음' if cfg.demo else '실장비 작업 시작 — AP별 순차 처리'})
        try:
            for index, ap_ip in enumerate(cfg.ap_ips, 1):
                self._current_result = None
                self._current_emitted = False
                self._emit('progress', {'index': index, 'total': len(cfg.ap_ips), 'ap_ip': ap_ip})
                prior = previous.get(ap_ip)
                if prior is not None and prior.status in GOOD_STATUSES:
                    result = replace(prior)
                    self._current_result = result
                    self._emit('log', {'message': f'{ap_ip} · 이전 작업 완료 결과 유지'})
                else:
                    result = Result(datetime.now().astimezone().isoformat(timespec='seconds'),
                                    ap_ip, '미실행', mode=mode, simulated=cfg.demo,
                                    target_ip=cfg.server_ip if mode in ('apply', 'verify_ip') else '',
                                    key_check='검사안함' if mode == 'verify_ip' else '')
                    mapped_name = safe_hostname(cfg.ap_hostnames.get(ap_ip, ''),
                                                (cfg.controller_password, cfg.ap_password, cfg.shared_key))
                    if mapped_name:
                        result.hostname, result.hostname_source = mapped_name, 'CSV'
                    self._current_result = result
                    if prior is not None:
                        # These fields contain no secrets. Preserve the original NAT goal and
                        # possible-write flag even if an earlier session never returned a reply.
                        for name in ('before_ip', 'before_nat', 'after_ip', 'after_nat', 'key_check',
                                     'config_sent', 'expected_nat', 'attempts', 'duration_seconds',
                                     'summary_before', 'summary_after', 'wips_mode', 'ip_check',
                                     'hostname', 'hostname_source', 'observed_at'):
                            setattr(result, name, getattr(prior, name))
                    if aborted or self.stop.is_set():
                        result.message = '중지 또는 앞선 오류로 실행하지 않았습니다.'
                    else:
                        start = time.monotonic()
                        old_duration = result.duration_seconds
                        for local_attempt in range(1, 2 + (cfg.max_retries if cfg.auto_recover else 0)):
                            if self.stop.is_set():
                                self._cancel_result(result)
                                break
                            result.attempts += 1
                            result.error_code = ''
                            if session is None:
                                try:
                                    session = factory(cfg, self.stop, self.confirm)
                                except Exception:
                                    result.status, result.error_code = '실패', 'PREPARE_FAILED'
                                    result.message = 'Telnet/AP SSH 작업을 준비하지 못했습니다. 설치 상태를 확인하세요.'
                                    aborted = True
                                    break
                            if hasattr(session, 'set_observer'):
                                session.set_observer(lambda kind, data, current=result: self._observer(current, kind, data))
                            failure = self._one(session, ap_ip, mode, result)
                            from .transport import TransportError
                            retry = (isinstance(failure, TransportError)
                                     and getattr(failure, 'retryable', False)
                                     and cfg.auto_recover and local_attempt <= cfg.max_retries
                                     and not self.stop.is_set())
                            if not retry:
                                break
                            # A new authenticated controller session is mandatory; never reuse
                            # an uncertain CLI position or retransmit the last command directly.
                            self._close(session)
                            session = None
                            delay = cfg.retry_delays[local_attempt - 1]
                            self._stage(result, '복구 대기')
                            self._emit('retry', {'ap_ip': ap_ip, 'attempt': local_attempt + 1,
                                                 'max_attempts': cfg.max_retries + 1,
                                                 'delay': delay, 'error_code': result.error_code})
                            self._emit('log', {'message': f'{ap_ip} · 통신 오류 후 재접속 {local_attempt}/{cfg.max_retries}; 현재 설정부터 재조회합니다.'})
                            if self.stop.wait(delay):
                                self._cancel_result(result)
                                break
                        result.duration_seconds = round(old_duration + time.monotonic() - start, 3)
                        if session is None or not session.controller_ready:
                            aborted = True
                        if cfg.stop_on_error and result.status not in GOOD_STATUSES:
                            aborted = True
                self.results.append(result)
                self._emit('result', {'result': result})
                self._current_emitted = True
                self._emit('log', {'message': f'{ap_ip} | {result.status} | {result.message}'})
        except Exception:
            # A worker/event error must retain any possible remote write. Without
            # this snapshot a manual resume could mistake this AP for untouched.
            current = self._current_result
            if current is not None and not self._current_emitted:
                current.status = '확인불가' if current.config_sent else '실패'
                if not current.error_code: current.error_code = 'INTERNAL_ERROR'
                current.message = '작업 상태 처리 오류로 중단했습니다. 현재 설정을 다시 확인한 뒤 이어가야 합니다.'
            raise
        finally:
            self._close(session)
            if not self._event_failed:
                self._emit('done', {'cancelled': self.stop.is_set()})
        return self.results

    def _cancel_result(self, result):
        result.error_code = 'CANCELLED'
        if result.config_sent:
            result.status = '확인불가'
            result.message = '중지 요청으로 복구를 종료했습니다. 이미 전달된 변경은 재조회가 필요합니다.'
        else:
            result.status = '중지'
            result.message = '사용자가 작업을 중지했습니다. 추가 접속이나 변경을 실행하지 않았습니다.'

    def _one(self, session, ap_ip, mode, result):
        from .transport import TransportError
        connected = False
        failure = None
        try:
            self._stage(result, '접속')
            self._emit('log', {'message': f'{ap_ip} · AP SSH 접속 시작'})
            session.connect(ap_ip)
            connected = True
            self._capture_hostname(session, result)
            result.controller_return = '미확인'
            self._emit('log', {'message': f'{ap_ip} · AP 로그인 확인'})
            if self.stop.is_set(): raise InterruptedError()
            self._perform(session, mode, result)
        except Exception as exc:
            self._capture_hostname(session, result)
            # Even if the transport wrapped a callback exception, a failed event
            # sink must escape the runner instead of looking like a device failure.
            if self._event_failed:
                raise EventDeliveryError('작업 상태를 기록하거나 전달하지 못했습니다.') from None
            failure = exc
            result.error_code = self._error_code(exc)
            if self.stop.is_set(): result.error_code = 'CANCELLED'
            if result.config_sent:
                result.status = '확인불가'
                result.message = '변경 명령이 전달되었을 수 있으나 검증을 마치지 못했습니다. 재조회 후 판단하세요.'
            elif self.stop.is_set():
                result.status = '중지'
                result.message = ('설정 변경 없이 조회한 결과를 보존하고 작업을 중지했습니다.'
                                  if mode == 'verify_ip' and result.after_ip else '변경 명령 전 중지했습니다.')
            else:
                result.status = '실패'
                result.message = f'{result.stage} 단계 오류. IP·포트·계정·Telnet/AP SSH 접속과 조회 형식을 확인하세요.'
                if isinstance(exc, TransportError): result.message = str(exc)
            if isinstance(exc, ValueError):
                result.error_code = 'SUMMARY_INVALID'
                if not result.config_sent:
                    result.message = ('WIPS 서버 IP 조회가 거부되었거나 단일 유효한 서버 IP 항목을 해석하지 못했습니다. 설정은 변경하지 않았습니다.'
                                      if mode == 'verify_ip' else '사전 조회를 해석하지 못했거나 필요한 NAT 값이 없습니다. 변경하지 않았습니다.')
        finally:
            failed_stage = result.stage if result.error_code else None
            if connected:
                try:
                    if self.stop.is_set() or self._event_failed:
                        raise InterruptedError()
                    self._stage(result, '컨트롤러 복귀')
                    self._emit('log', {'message': f'{ap_ip} · exit로 컨트롤러 복귀 시도'})
                    session.leave_ap()
                    if not session.controller_ready:
                        raise RuntimeError('controller not verified')
                    result.controller_return = '복귀확인'
                    self._emit('log', {'message': f'{ap_ip} · 컨트롤러 복귀 확인'})
                except Exception as exc:
                    if self._event_failed:
                        self._close(session)
                        raise EventDeliveryError('작업 상태를 기록하거나 전달하지 못했습니다.') from None
                    result.controller_return = '미확인'
                    if result.status in GOOD_STATUSES:
                        result.status = '복귀실패'
                        result.error_code = self._error_code(exc)
                        # Do not hide a primary authentication/parser/CLI failure by
                        # retrying a secondary exit timeout.
                        if failure is None: failure = exc
                        failed_stage = '컨트롤러 복귀'
                    result.message += ' 컨트롤러 복귀를 확인하지 못했습니다.'
                    self._close(session)
            if failed_stage is not None:
                result.stage = failed_stage
            elif result.status in GOOD_STATUSES:
                self._stage(result, '완료')
        return failure

    def _perform(self, session, mode, result):
        cfg = self.config
        ambiguous = result.config_sent
        self._stage(result, '사전 조회')
        response = session.execute(SUMMARY_COMMAND)
        self._capture_summary(result, response, mode, after=ambiguous and mode == 'apply')
        if cli_error(response):
            result.status, result.error_code = '실패', 'CLI_REJECTED'
            result.message = '사전 조회 명령을 장비가 거부했습니다. 자동 재시도하지 않습니다.'
            return
        if mode == 'verify_ip':
            result.before_ip = result.after_ip = parse_server_ip(response)
            result.ip_check = '일치' if result.after_ip == cfg.server_ip else '불일치'
            result.status = 'IP일치' if result.ip_check == '일치' else 'IP불일치'
            result.message = ('설정 변경 없이 조회한 WIPS 서버 IP가 지정한 값과 '
                              + ('일치합니다.' if result.ip_check == '일치' else '다릅니다.'))
            if self.stop.is_set(): raise InterruptedError()
            return
        before = parse_summary(response)
        if mode == 'inspect' or not result.before_ip:
            result.before_ip, result.before_nat = before.server_ip, before.nat or ''
        if self.stop.is_set(): raise InterruptedError()
        if mode == 'inspect':
            result.after_ip, result.after_nat = before.server_ip, before.nat or ''
            result.status = '조회완료'
            result.message = '현재 설정 조회 완료. 공유키는 장비가 반환한 값으로 표시합니다.'
            return
        expected_nat = ((result.expected_nat or None) if ambiguous
                        else (before.nat if cfg.nat_mode == 'keep' else cfg.nat_mode))
        if not ambiguous: result.expected_nat = expected_nat or ''
        if ambiguous and (expected_nat is None or before.nat is None or before.shared_key is None):
            result.status, result.error_code = '부분확인', 'RECOVERY_UNVERIFIABLE'
            result.after_ip, result.after_nat = before.server_ip, before.nat or ''
            result.key_check = '확인불가' if before.shared_key is None else ('일치' if before.shared_key == cfg.shared_key else '불일치')
            result.message = '복구 조회에서 키 또는 기존 NAT 목표를 완전히 확인하지 못했습니다. 변경 명령을 재전송하지 않았습니다.'
            return
        if cfg.syntax == 'with_nat' and expected_nat is None:
            raise ValueError('기존 NAT 값을 확인할 수 없어 변경하지 않았습니다.')
        if before.server_ip == cfg.server_ip and before.shared_key == cfg.shared_key and before.nat == expected_nat:
            result.status, result.key_check = '이미일치', '일치'
            result.after_ip, result.after_nat = before.server_ip, before.nat or ''
            result.message = '서버 IP·키·NAT가 이미 일치하여 변경 명령을 생략했습니다.'
            if expected_nat is None:
                result.status, result.error_code = '부분확인', 'VERIFICATION_PARTIAL'
                result.message = '서버 IP·키는 이미 일치하여 변경하지 않았으나 NAT는 확인할 수 없습니다.'
            return
        args = ['config', 'wips', 'server', cfg.server_ip]
        if cfg.syntax == 'with_nat': args.append(expected_nat)
        args.append(cfg.shared_key)
        if self.stop.is_set(): raise InterruptedError()
        # Set this before emitting/sending: a failed send can be partially delivered.
        result.config_sent = True
        result.ip_check = ''  # A prior read is no longer evidence of the post-write value.
        result.after_ip = result.after_nat = ''
        self._stage(result, '변경 명령')
        response = session.execute(' '.join(args))
        if cli_error(response):
            result.status, result.error_code = '실패', 'CLI_REJECTED'
            result.message = '변경 명령 오류 응답. 다른 문법으로 자동 재시도하지 않았습니다. 재조회가 필요합니다.'
            return
        if self.stop.is_set(): raise InterruptedError()
        self._stage(result, '변경 후 조회')
        response = session.execute(SUMMARY_COMMAND)
        self._capture_summary(result, response, mode, after=True)
        if cli_error(response):
            result.status, result.error_code = '확인불가', 'CLI_REJECTED'
            result.message = '변경 후 조회 명령을 장비가 거부했습니다. 자동 재시도하지 않습니다.'
            return
        after = parse_summary(response)
        result.after_ip, result.after_nat = after.server_ip, after.nat or ''
        result.key_check = '확인불가' if after.shared_key is None else ('일치' if after.shared_key == cfg.shared_key else '불일치')
        nat_bad = expected_nat is not None and after.nat is not None and after.nat != expected_nat
        if after.server_ip != cfg.server_ip or result.key_check == '불일치' or nat_bad:
            result.status, result.error_code = '검증불일치', 'VERIFICATION_MISMATCH'
            result.message = '조회된 서버 IP·키·NAT 중 목표와 다른 값이 있습니다.'
        elif result.key_check == '확인불가' or after.nat is None or expected_nat is None:
            result.status, result.error_code = '부분확인', 'VERIFICATION_PARTIAL'
            result.message = '서버 IP는 일치하지만 키 또는 NAT를 완전히 검증할 수 없습니다.'
        else:
            result.status = '변경확인'
            result.message = '설정값 일치 확인. WIPS 서버 연결·인증 상태는 별도 확인 대상입니다.'

    def _capture_summary(self, result, response, mode, after=False):
        cfg = self.config
        secrets = (cfg.controller_password, cfg.ap_password, cfg.shared_key)
        safe = _safe_summary_fields(response, secrets)
        text = safe_summary_text(response, secrets, reveal_shared_key=True)
        if after:
            result.summary_after = text
            result.after_ip, result.after_nat = safe.get('server_ip', ''), safe.get('nat', '')
        elif mode in ('inspect', 'verify_ip') or not result.summary_before:
            result.summary_before = text
        result.wips_mode = safe.get('mode', '')
        if safe.get('server_ip'):
            result.observed_at = datetime.now().astimezone().isoformat(timespec='seconds')
        if mode in ('apply', 'verify_ip'):
            current = safe.get('server_ip')
            result.ip_check = (('일치' if current == cfg.server_ip else '불일치') if current else '')

    def _capture_hostname(self, session, result):
        """Controller name wins; CSV is fallback before a non-generic AP prompt."""
        cfg = self.config
        secrets = (cfg.controller_password, cfg.ap_password, cfg.shared_key)
        try:
            reported = safe_hostname(getattr(session, 'ap_hostname', ''), secrets)
            source = getattr(session, 'hostname_source', '')
        except Exception:
            reported, source = '', ''
        mapped = safe_hostname(cfg.ap_hostnames.get(result.ap_ip, ''), secrets)
        if reported and source == '컨트롤러 AP_NAME':
            result.hostname, result.hostname_source = reported, source
        elif mapped:
            result.hostname, result.hostname_source = mapped, 'CSV'
        elif (reported and source == 'AP 프롬프트'
              and reported.casefold() not in ('ap', 'root', 'admin', 'sh', 'bash', 'busybox', 'cli', 'localhost')):
            result.hostname, result.hostname_source = reported, source
