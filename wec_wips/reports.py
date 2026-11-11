"""Offline report exports from allowlisted AP results, never connection config."""
from __future__ import annotations

import html
import ipaddress
import json
import math
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import fields
from datetime import datetime
from pathlib import Path

from .core import GOOD_STATUSES, Result, export_results

_FIELDS = (
    'time', 'ap_ip', 'hostname', 'hostname_source', 'observed_at', 'status', 'target_ip', 'after_ip', 'before_ip', 'before_nat',
    'after_nat', 'key_check', 'message', 'mode', 'simulated', 'controller_return',
    'ip_check', 'attempts', 'error_code', 'stage', 'duration_seconds', 'config_sent',
    'expected_nat', 'summary_before', 'summary_after', 'wips_mode',
)
_FAILED = frozenset(('실패', '복귀실패', '확인불가', '중지'))
_IP_FIELDS = frozenset(('ap_ip', 'target_ip', 'after_ip', 'before_ip'))


def _text(value, limit=4096):
    if not isinstance(value, str):
        return ''
    return ''.join(c for c in value[:limit] if ord(c) >= 32 or c in '\n\r\t')


def _ip(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        return ''


def _number(value, maximum=100000000):
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum:
        return value
    return 0


def _summary(value):
    from .core import safe_summary_text
    return safe_summary_text(value, reveal_shared_key=True) if isinstance(value, str) and value else ''


def report_rows(results):
    """A JSON-safe, fixed schema; dynamic attributes and credentials are ignored."""
    rows = []
    for result in results:
        if not isinstance(result, Result):
            raise TypeError('AP 작업 결과만 보고서로 저장할 수 있습니다.')
        row = {}
        for name in _FIELDS:
            value = getattr(result, name, '')
            if name in _IP_FIELDS:
                row[name] = _ip(value)
            elif name in ('simulated', 'config_sent'):
                row[name] = value is True
            elif name in ('attempts', 'duration_seconds'):
                row[name] = _number(value)
            elif name in ('summary_before', 'summary_after'):
                row[name] = _summary(value)
            elif name in ('before_nat', 'after_nat', 'expected_nat'):
                row[name] = value if value in ('1', '2') else ''
            elif name == 'wips_mode':
                row[name] = value if isinstance(value, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,58}MODE', value) else ''
            elif name == 'hostname':
                row[name] = _text(value, 128)
            elif name == 'hostname_source':
                row[name] = value if value in ('컨트롤러 AP_NAME', 'AP 프롬프트', 'CSV') else ''
            elif name == 'observed_at':
                row[name] = _text(value, 64)
            else:
                row[name] = _text(value)
        if row['status'] == '미실행':
            category = 'unexecuted'
        elif row['status'] in _FAILED:
            category = 'failed'
        elif row['ip_check'] == '불일치':
            category = 'mismatch'
        elif row['ip_check'] == '일치':
            category = 'match'
        else:
            category = 'unknown'
        row['category'] = category
        row['attention'] = row['status'] not in GOOD_STATUSES
        rows.append(row)
    return rows


def _json_for_html(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':'))
            .replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
            .replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))


def render_html(results, title='WIPS AP 조회 보고서'):
    """Render a standalone HTML report; no server, CDN, external font or telemetry."""
    rows = report_rows(results)
    title = _text(title, 160)
    counts = dict(total=len(rows), match=0, mismatch=0, failed=0, unexecuted=0, unknown=0)
    for row in rows:
        counts[row['category']] += 1
    data = {'version': '1.5.1', 'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
            'title': title, 'rows': rows, 'counts': counts}
    template = Path(__file__).with_name('report_template.html').read_text(encoding='utf-8')
    if '__REPORT_DATA__' not in template or '__REPORT_TITLE__' not in template:
        raise ValueError('보고서 화면 파일을 확인할 수 없습니다.')
    replacements = {'__REPORT_TITLE__': html.escape(title, quote=True),
                    '__REPORT_DATA__': _json_for_html(data)}
    # Substitute the original template once; values containing token-like strings
    # are data and must never be interpreted as another template replacement.
    return re.sub(r'__REPORT_(?:TITLE|DATA)__', lambda match: replacements[match.group()], template)


def _safe_results(rows):
    names = {field.name for field in fields(Result)}
    return [Result(**{name: value for name, value in row.items() if name in names}) for row in rows]


def _new_folder(parent_dir, prefix, writer):
    parent = Path(parent_dir)
    parent.mkdir(parents=True, exist_ok=True)
    name = f'{prefix}_{datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:8]}'
    target = parent / name
    staging = Path(tempfile.mkdtemp(prefix='.wips-export-', dir=parent))
    try:
        writer(staging)
        # Rename only the newly created staging directory; existing exports are untouched.
        if target.exists():
            raise FileExistsError('같은 이름의 보고서 폴더가 있습니다. 다시 저장하세요.')
        staging.rename(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target


def write_report_bundle(parent_dir, results, title='WIPS AP 조회 보고서'):
    """Save report.html and UTF-8-BOM results.csv under one new run directory."""
    safe_results = _safe_results(report_rows(list(results)))
    document = render_html(safe_results, title)
    def write(folder):
        (folder / 'report.html').write_text(document, encoding='utf-8')
        export_results(folder / 'results.csv', safe_results)
    return _new_folder(parent_dir, 'wips_report', write)


def _detail_text(row):
    current = row['after_ip'] or (row['before_ip'] if row['mode'] in ('inspect', 'verify_ip') else '')
    labels = [
        ('AP IP', row['ap_ip']), ('호스트명', row['hostname']), ('호스트명 출처', row['hostname_source']),
        ('작업 시작 시각', row['time']), ('조회 시각', row['observed_at']), ('결과', row['status']),
        ('실행', '모의 실행' if row['simulated'] else '실제 장비'),
        ('목표 서버 IP', row['target_ip']), ('조회된 서버 IP', current),
        ('IP 비교', row['ip_check']), ('변경 전 서버 IP', row['before_ip']),
        ('NAT 전', row['before_nat']), ('NAT 후', row['after_nat']),
        ('WIPS 모드', row['wips_mode']), ('키 확인', row['key_check']),
        ('컨트롤러 복귀', row['controller_return']), ('시도 수', row['attempts']),
        ('단계', row['stage']), ('오류 코드', row['error_code']),
        ('경과 시간(초)', row['duration_seconds']), ('설명', row['message']),
    ]
    text = ['WEC8500 WIPS AP 상세 결과', '조회 항목 정리본 (장비가 반환한 WIPS 공유키 포함)', '']
    text.extend(f'{name}: {value if value != "" else "-"}' for name, value in labels)
    text.extend(('', '[최초/조회 전 설정]', row['summary_before'] or '수집된 항목 없음',
                 '', '[변경 후/복구 조회 설정]', row['summary_after'] or '수집된 항목 없음',
                 '', 'WIPS 공유키는 장비가 반환한 값으로 표시합니다. 장비가 가린 값은 복원할 수 없습니다.',
                 '로그인 정보·장비 응답 원문·미인식 항목은 저장하지 않습니다.',
                 '이 보고서는 설정 조회 결과이며 WIPS 서버 연결·인증 상태 확인이 아닙니다.', ''))
    return '\n'.join(text)


def export_ap_txt(path, result):
    """Write one operator-selected path atomically, excluding raw CLI responses."""
    row = report_rows([result])[0]
    text = _detail_text(row)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.wips-detail-', suffix='.tmp', dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8-sig', newline='') as handle:
            handle.write(text)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def export_ap_txts(parent_dir, results):
    """Save selected APs only; validate filenames before touching the destination."""
    results = list(results)
    if not results:
        raise ValueError('TXT로 저장할 AP를 선택하세요.')
    names = []
    occurrences = {}
    for result in results:
        ip = _ip(getattr(result, 'ap_ip', ''))
        if not ip:
            raise ValueError('AP IP가 올바르지 않아 상세 파일을 저장하지 않았습니다.')
        occurrences[ip] = occurrences.get(ip, 0) + 1
        suffix = '' if occurrences[ip] == 1 else f'_{occurrences[ip]}'
        names.append(ip + suffix + '.txt')
    safe_results = _safe_results(report_rows(results))
    def write(folder):
        details = folder / 'details'
        details.mkdir()
        for name, result in zip(names, safe_results):
            export_ap_txt(details / name, result)
    return _new_folder(parent_dir, 'wips_details', write)
