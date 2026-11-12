"""One local profile: allowlisted settings plus current-user DPAPI secret blocks.

No controller credentials, device results, raw terminal data or automatic saves.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .core import KEY_PATTERN, USER_PATTERN, _ipv4, parse_ap_ips, safe_hostname
from .dpapi import DpapiProtector
from .profile_errors import ProfileError
from .profile_lock import exclusive_profile_lock

MAX_FILE = 2 * 1024 * 1024
SECRET_NAMES = frozenset(('ap_password', 'shared_key'))
DEFAULTS = dict(controller_ip='', controller_port=23, ap_user='root', ap_port=50022,
                server_ip='', syntax='with_nat', nat_mode='keep', timeout=20,
                auto_recover=True, stop_on_error=True, auto_accept_ap_host_key=True,
                lookup_hostnames=True, ap_ips=[], ap_hostnames={})


_OBSERVED = object()


@dataclass
class Profile:
    settings: dict
    secrets: dict = field(repr=False)
    revision: str = field(default="", repr=False)


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def _decode(data):
    return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))


def normalize_settings(settings):
    try:
        if not isinstance(settings, dict) or set(settings) - set(DEFAULTS):
            raise ValueError('unknown settings')
        value = copy.deepcopy(DEFAULTS)
        value.update(copy.deepcopy(settings))
        value['controller_ip'] = _ipv4(value['controller_ip'], '컨트롤러 IP')
        for name in ('controller_port', 'ap_port'):
            if type(value[name]) is not int or not 1 <= value[name] <= 65535:
                raise ValueError('port')
        if not isinstance(value['ap_user'], str) or not USER_PATTERN.fullmatch(value['ap_user']):
            raise ValueError('AP user')
        if not isinstance(value['server_ip'], str):
            raise ValueError('server')
        value['server_ip'] = (_ipv4(value['server_ip'], 'WIPS 서버 IP')
                              if value['server_ip'].strip() else '')
        if value['syntax'] not in ('with_nat', 'without_nat') or value['nat_mode'] not in ('keep', '1', '2'):
            raise ValueError('syntax')
        if value['syntax'] == 'without_nat' and value['nat_mode'] != 'keep':
            raise ValueError('NAT')
        if (type(value['timeout']) not in (int, float) or not math.isfinite(value['timeout'])
                or not 2 <= value['timeout'] <= 120):
            raise ValueError('timeout')
        for name in ('auto_recover', 'stop_on_error', 'auto_accept_ap_host_key', 'lookup_hostnames'):
            if type(value[name]) is not bool:
                raise ValueError('option')
        ips = value['ap_ips']
        if not isinstance(ips, list) or any(not isinstance(ip, str) for ip in ips):
            raise ValueError('AP list')
        value['ap_ips'] = parse_ap_ips('\n'.join(ips)) if ips else []
        if value['controller_ip'] in value['ap_ips']:
            raise ValueError('controller target')
        names = value['ap_hostnames']
        if not isinstance(names, dict):
            raise ValueError('names')
        normalized = {}
        for ip, name in names.items():
            ip = _ipv4(ip, 'AP IP')
            clean = safe_hostname(name)
            if not clean or ip not in value['ap_ips'] or ip in normalized:
                raise ValueError('hostname')
            normalized[ip] = clean
        value['ap_hostnames'] = normalized
        if len(_json(value)) > MAX_FILE // 2:
            raise ValueError('too large')
        return value
    except Exception:
        raise ProfileError('저장할 설정의 IP·포트·AP 계정·옵션·목록을 확인하세요.') from None


def binding(settings, kind):
    if kind not in SECRET_NAMES:
        raise ProfileError('지원하지 않는 비밀정보 종류입니다.')
    names = ('controller_ip', 'controller_port', 'ap_user', 'ap_port')
    value = {name: settings[name] for name in names}
    if kind == 'shared_key':
        value['server_ip'] = settings['server_ip']
    return value


def _secret_value(kind, value):
    if not isinstance(value, str):
        raise ProfileError('저장할 비밀번호 또는 공유키를 입력하세요.')
    if kind == 'ap_password':
        valid = 1 <= len(value) <= 1024 and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    else:
        valid = bool(KEY_PATTERN.fullmatch(value))
    if not valid:
        raise ProfileError('비밀번호 또는 공유키의 길이·지원 문자를 확인하세요.')
    return value


def default_directory():
    if sys.platform != 'win32':
        raise ProfileError('설정 저장은 Windows에서 지원합니다. 수동 입력으로 사용할 수 있습니다.')
    root = os.environ.get('LOCALAPPDATA')
    if not root or not Path(root).is_absolute():
        raise ProfileError('Windows 사용자 저장 위치를 확인하지 못했습니다.')
    return Path(root) / 'WEC8500_WIPS_Manager' / 'settings'


class ProfileStore:
    def __init__(self, directory=None, protector=None):
        self.directory = Path(directory) if directory is not None else default_directory()
        self.path = self.directory / 'profile.json'
        self.protector = protector if protector is not None else DpapiProtector()
        self._observed_revision = None

    @property
    def observed_revision(self):
        return self._observed_revision

    def _read_raw(self):
        try:
            if self.path.is_symlink():
                raise PermissionError()
            try:
                with self.path.open('rb') as handle:
                    data = handle.read(MAX_FILE + 1)
            except FileNotFoundError:
                return None
            if len(data) > MAX_FILE:
                raise ProfileError(code='PROFILE_FORMAT_INVALID')
            return data
        except PermissionError:
            raise ProfileError(code='PROFILE_ACCESS_DENIED') from None
        except OSError:
            raise ProfileError(code='PROFILE_READ_FAILED') from None

    @staticmethod
    def _revision(raw):
        return None if raw is None else hashlib.sha256(raw).hexdigest()

    def _check_current(self, expected_revision):
        if expected_revision != self._revision(self._read_raw()):
            raise ProfileError(code='PROFILE_CHANGED')

    def assert_current(self, expected_revision):
        # Reads never implicitly accept a new version. The caller must load it.
        with exclusive_profile_lock(self.directory):
            self._check_current(expected_revision)

    def load(self):
        raw = self._read_raw()
        self._observed_revision = self._revision(raw)
        if raw is None:
            return None
        try:
            doc = _decode(raw)
            if (not isinstance(doc, dict) or set(doc) != {'schema', 'settings', 'secrets'}
                    or type(doc['schema']) is not int or doc['schema'] != 1):
                raise ValueError('schema')
            if not isinstance(doc['settings'], dict) or set(doc['settings']) != set(DEFAULTS):
                raise ValueError('incomplete settings')
            settings = normalize_settings(doc['settings'])
            secrets = doc['secrets']
            if not isinstance(secrets, dict) or set(secrets) - SECRET_NAMES:
                raise ValueError('secret schema')
            for token in secrets.values():
                if not isinstance(token, str) or len(token) > 180000:
                    raise ValueError('token')
                encrypted = base64.b64decode(token, validate=True)
                if not 1 <= len(encrypted) <= DpapiProtector.MAX_DATA:
                    raise ValueError('size')
            return Profile(settings, dict(secrets), self._observed_revision)
        except Exception:
            raise ProfileError(code='PROFILE_FORMAT_INVALID') from None

    def secret(self, profile, kind, current_settings):
        try:
            self.assert_current(profile.revision)
            current = normalize_settings(current_settings)
            expected = binding(profile.settings, kind)
            if expected != binding(current, kind):
                raise ProfileError('접속 대상이나 AP 계정이 달라 저장된 비밀정보를 사용할 수 없습니다. 다시 입력하세요.')
            if kind not in profile.secrets:
                raise ProfileError('저장된 비밀번호 또는 공유키가 없습니다. 직접 입력하세요.')
            entropy = _json({'app': 'WEC8500-profile', 'schema': 1, 'kind': kind, 'binding': expected})
            raw = base64.b64decode(profile.secrets[kind], validate=True)
            plain = self.protector.unprotect(raw, entropy)
            if not isinstance(plain, bytes) or len(plain) > 16384:
                raise ValueError('decrypted size')
            doc = _decode(plain)
            if (not isinstance(doc, dict) or set(doc) != {'schema','kind','binding','value'}
                    or type(doc['schema']) is not int or doc['schema'] != 1
                    or doc['kind'] != kind or doc['binding'] != expected):
                raise ValueError('payload')
            value = _secret_value(kind, doc['value'])
            # Crypto may be slow; reject updates/deletions made while it ran.
            self.assert_current(profile.revision)
            return value
        except ProfileError:
            raise
        except Exception:
            raise ProfileError(code='PROFILE_DECRYPT_FAILED') from None

    def save(self, settings, *, ap_password=None, shared_key=None, expected_revision=_OBSERVED):
        expected_revision = self._observed_revision if expected_revision is _OBSERVED else expected_revision
        settings = normalize_settings(settings)
        # Early check is advisory; compare again under the commit lock after crypto.
        self._check_current(expected_revision)
        tokens = {}
        try:
            for kind, value in (('ap_password', ap_password), ('shared_key', shared_key)):
                if value is None:
                    continue
                value = _secret_value(kind, value)
                expected = binding(settings, kind)
                if kind == 'shared_key' and not settings['server_ip']:
                    raise ProfileError('공유키를 저장하려면 목표 WIPS 서버 IP를 입력하세요.')
                entropy = _json({'app':'WEC8500-profile','schema':1,'kind':kind,'binding':expected})
                plain = _json({'schema':1,'kind':kind,'binding':expected,'value':value})
                encrypted = self.protector.protect(plain, entropy)
                if not isinstance(encrypted, bytes) or not 1 <= len(encrypted) <= DpapiProtector.MAX_DATA:
                    raise ValueError('ciphertext')
                tokens[kind] = base64.b64encode(encrypted).decode('ascii')
            encoded = _json({'schema':1,'settings':settings,'secrets':tokens})
            if len(encoded) > MAX_FILE:
                raise ValueError('size')
        except ProfileError:
            raise
        except Exception:
            raise ProfileError(code='PROFILE_PROTECT_FAILED') from None
        with exclusive_profile_lock(self.directory):
            self._check_current(expected_revision)
            self._write_atomic(encoded)
            self._observed_revision = self._revision(encoded)
        return Profile(settings, tokens, self._observed_revision)

    def _write_atomic(self, encoded):
        temporary = None
        fd = None
        try:
            if self.path.is_symlink():
                raise PermissionError()
            fd, name = tempfile.mkstemp(prefix='.profile-', suffix='.tmp', dir=self.directory)
            temporary = Path(name)
            handle = os.fdopen(fd, 'wb')
            fd = None
            with handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except PermissionError:
            raise ProfileError(code='PROFILE_ACCESS_DENIED') from None
        except Exception:
            raise ProfileError(code='PROFILE_WRITE_FAILED') from None
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def delete(self, *, expected_revision=_OBSERVED):
        expected_revision = self._observed_revision if expected_revision is _OBSERVED else expected_revision
        with exclusive_profile_lock(self.directory):
            self._check_current(expected_revision)
            try:
                self.path.unlink(missing_ok=True)
            except PermissionError:
                raise ProfileError(code='PROFILE_ACCESS_DENIED') from None
            except OSError:
                raise ProfileError(code='PROFILE_DELETE_FAILED') from None
            self._observed_revision = None
