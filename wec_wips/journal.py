"""Local diagnostic records. Never serialize config objects or terminal text."""
from __future__ import annotations

import csv
import ipaddress
import json
import math
import os
import re
import time
import uuid
from dataclasses import fields
from datetime import datetime
from pathlib import Path

from .core import Result, safe_hostname, safe_summary_text

STAGES = frozenset(('접속', '사전 조회', '변경 명령', '변경 후 조회', '컨트롤러 복귀',
                    '복구 대기', '재접속', '완료', '컨트롤러 연결', '컨트롤러 로그인',
                    'AP 로그인', 'AP 이름 조회', 'exit'))
STATUSES = frozenset(('미실행', '조회완료', '변경확인', '이미일치', 'IP일치', 'IP불일치',
                      '실패', '중지', '확인불가', '부분확인', '검증불일치', '복귀실패'))
ERROR_CODES = frozenset(('TRANSPORT_ERROR', 'CONTROLLER_CONNECT_TIMEOUT',
    'CONTROLLER_CONNECT_FAILED', 'CONTROLLER_LOGIN_TIMEOUT', 'AP_CONNECT_FAILED',
    'AP_LOGIN_TIMEOUT', 'COMMAND_TIMEOUT', 'RETURN_TIMEOUT', 'CONNECTION_CLOSED',
    'IO_ERROR', 'CANCELLED', 'AUTH_FAILED', 'CONTROLLER_AUTH_FAILED', 'AP_AUTH_FAILED',
    'HOST_KEY_CHANGED', 'HOST_KEY_REJECTED', 'UNEXPECTED_DATA', 'INVALID_INPUT',
    'PROMPT_MISMATCH', 'PARSE_ERROR', 'CLI_ERROR', 'VERIFY_MISMATCH',
    'PARTIAL_VERIFICATION', 'RETURN_FAILED', 'SESSION_NOT_READY', 'INTERNAL_ERROR', 'PROTOCOL_ERROR', 'PREPARE_FAILED', 'SUMMARY_INVALID', 'CLI_REJECTED',
    'RECOVERY_UNVERIFIABLE', 'VERIFICATION_PARTIAL', 'VERIFICATION_MISMATCH'))


def _ip(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        return ''



def _choice(value, choices):
    return value if isinstance(value, str) and value in choices else ''


def _number(value, maximum=1000000):
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum:
        return value
    return 0


def _timestamp():
    return datetime.now().astimezone().isoformat(timespec='seconds')


def _safe_time(value):
    if not isinstance(value, str) or not value or len(value) > 40:
        return ''
    try:
        return datetime.fromisoformat(value).isoformat(timespec='seconds')
    except ValueError:
        return ''


def safe_result(result, secrets=()):
    # Construct a new result with defaults so no object repr or unlisted field leaks.
    safe = Result(_safe_time(getattr(result, 'time', '')) or _timestamp(), _ip(getattr(result, 'ap_ip', '')),
                  _choice(getattr(result, 'status', ''), STATUSES))
    for name in ('before_ip', 'after_ip', 'target_ip'):
        setattr(safe, name, _ip(getattr(result, name, '')))
    for name in ('before_nat', 'after_nat', 'expected_nat'):
        if hasattr(safe, name):
            setattr(safe, name, _choice(getattr(result, name, ''), ('1', '2')))
    safe.key_check = _choice(getattr(result, 'key_check', ''),
                             ('일치', '불일치', '확인불가', '검사안함'))
    safe.ip_check = _choice(getattr(result, 'ip_check', ''), ('일치', '불일치'))
    safe.controller_return = _choice(getattr(result, 'controller_return', ''),
                                     ('미접속', '미확인', '복귀확인'))
    safe.mode = _choice(getattr(result, 'mode', ''), ('inspect', 'apply', 'verify_ip'))
    safe.simulated = getattr(result, 'simulated', False) is True
    for name in ('attempts', 'duration_seconds'):
        if hasattr(safe, name):
            setattr(safe, name, _number(getattr(result, name, 0)))
    if hasattr(safe, 'config_sent'):
        safe.config_sent = getattr(result, 'config_sent', False) is True
    if hasattr(safe, 'stage'):
        safe.stage = _choice(getattr(result, 'stage', ''), STAGES)
    if hasattr(safe, 'error_code'):
        safe.error_code = _choice(getattr(result, 'error_code', ''), ERROR_CODES)
    for name in ('summary_before', 'summary_after'):
        value = getattr(result, name, '')
        if isinstance(value, str) and value:
            setattr(safe, name, safe_summary_text(value, secrets))
    mode = getattr(result, 'wips_mode', '')
    if (isinstance(mode, str) and re.fullmatch(r'WIPS_[A-Z0-9_]{1,48}_MODE', mode)
            and not any(secret and secret in mode for secret in secrets)):
        safe.wips_mode = mode
    safe.hostname = safe_hostname(getattr(result, 'hostname', ''), secrets)
    safe.hostname_source = (_choice(getattr(result, 'hostname_source', ''),
                                  ('컨트롤러 AP_NAME', 'CSV', 'AP 프롬프트')) if safe.hostname else '')
    safe.observed_at = _safe_time(getattr(result, 'observed_at', ''))
    return {f.name: getattr(safe, f.name) for f in fields(Result)}


class LocalJournal:
    """One local run directory. No network API, raw output, usernames or secrets."""
    def __init__(self, config, mode, base_dir=None):
        self._secrets = tuple(value for value in (config.controller_password, config.ap_password, config.shared_key)
                              if isinstance(value, str) and value)
        if base_dir is None:
            if os.name == 'nt':
                root = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local')
            else:
                root = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state')
            base_dir = root / 'WEC8500_WIPS_Manager' / 'records'
        self.directory = Path(base_dir) / (datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8])
        self.directory.mkdir(parents=True, mode=0o700)
        self._closed = False
        self._last_activity = 0.0
        self._state = {'schema': 1, 'time': _timestamp(), 'running': True,
                       'mode': _choice(mode, ('inspect', 'apply', 'verify_ip')),
                       'ap_ip': '', 'stage': '', 'attempt': 0, 'result_count': 0}
        self._events = None
        self._csv = None
        try:
            self._events = (self.directory / 'events.jsonl').open('w', encoding='utf-8')
            self._csv = (self.directory / 'results.csv').open('w', encoding='utf-8-sig', newline='')
            self._writer = csv.DictWriter(self._csv, fieldnames=[f.name for f in fields(Result)])
            self._writer.writeheader()
            self._csv.flush()
            self._write_json('job.json', {
                'schema': 1, 'created': _timestamp(), 'mode': self._state['mode'],
                'controller_ip': _ip(config.controller_ip),
                'controller_port': _number(config.controller_port, 65535),
                'ap_count': len(config.ap_ips), 'ap_port': _number(config.ap_port, 65535),
                'target_ip': _ip(config.server_ip), 'simulated': config.demo is True,
                'auto_recover': getattr(config, 'auto_recover', False) is True,
                'max_retries': _number(getattr(config, 'max_retries', 0), 2),
                'timeout_seconds': _number(config.timeout, 120),
                'note': 'PC 내부 진단 기록. 암호·공유키·장비 원문 없음. 자동 업로드 없음.',
            })
            self._write_json('state.json', self._state)
        except Exception:
            self.close()
            raise

    def _write_json(self, name, value):
        target = self.directory / name
        temporary = target.with_suffix(target.suffix + '.tmp')
        try:
            with temporary.open('w', encoding='utf-8') as f:
                json.dump(value, f, ensure_ascii=False, indent=2)
                f.flush()
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()

    def record(self, kind, data):
        if self._closed or kind not in ('stage', 'retry', 'activity', 'result', 'done', 'progress'):
            return
        if kind == 'activity':
            now = time.monotonic()
            if now - self._last_activity < 1:
                return
            self._last_activity = now
        event = {'time': _timestamp(), 'event': kind}
        if kind == 'result':
            row = safe_result(data['result'], self._secrets)
            self._writer.writerow(row)
            self._csv.flush()
            event.update(row)
            self._state['result_count'] += 1
        else:
            for key in ('ap_ip',):
                if key in data:
                    event[key] = _ip(data[key])
            for key in ('attempt', 'max_attempts', 'delay', 'index', 'total'):
                if key in data:
                    event[key] = _number(data[key])
            if 'stage' in data:
                event['stage'] = _choice(data['stage'], STAGES)
            if 'error_code' in data:
                event['error_code'] = _choice(data['error_code'], ERROR_CODES)
            if kind == 'done':
                event['cancelled'] = data.get('cancelled') is True
                self._state['running'] = False
        self._events.write(json.dumps(event, ensure_ascii=False) + '\n')
        self._events.flush()
        for name in ('time', 'ap_ip', 'stage', 'attempt', 'error_code'):
            if name in event:
                self._state[name] = event[name]
        if kind != 'activity':
            self._write_json('state.json', self._state)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._state['running']:
                self._state['running'] = False
                self._state['outcome'] = 'ended_before_done'
                self._write_json('state.json', self._state)
        finally:
            try:
                if self._events is not None:
                    self._events.close()
            finally:
                if self._csv is not None:
                    self._csv.close()
