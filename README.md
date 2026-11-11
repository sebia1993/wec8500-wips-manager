# WEC8500 WIPS Manager — Windows 보호 프로필 (profile.1)

기반: v1.5.1 stabilization.3 + 추가 안정성 검사 (`bb9d09b`).

반복 입력을 줄이는 기본 프로필 1개를 추가했습니다. 일반 설정은 자동 복원하고, 선택한 AP 비밀번호와 목표 WIPS 공유키는 Windows 사용자 범위 DPAPI로 암호화 저장합니다. **WEC8500 사용자 ID·비밀번호는 저장하지 않습니다. 자동 접속·자동 변경도 하지 않습니다.**

## 사용

1. Windows ZIP 전체를 새 폴더에 풀고 `WEC8500_WIPS_Manager_v1.5.1_profile.1_Win11_x64.exe`를 실행합니다.
2. 최초에는 모의 실행을 해제하고 일반 설정·AP 접속정보를 입력한 뒤 **설정 저장**을 누릅니다.
3. 저장할 AP 비밀번호·목표 공유키·AP 목록을 각각 선택하고 저장합니다. 최초 선택은 모두 꺼짐입니다.
4. 다음 실행부터 일반 설정과 저장된 비밀정보 사용 상태가 복원됩니다. WEC8500 ID·비밀번호를 입력하고 대상 확인 후 기존 작업 버튼을 누릅니다.

저장된 암호를 입력창에 다시 표시하지 않습니다. 빈 입력창이면 체크된 저장 정보를 사용하며, 직접 입력한 값이 우선합니다. 조회 전용에서는 저장된 목표 공유키를 복호화하지 않습니다. 프로필이 없거나 Windows 저장을 지원하지 않는 환경에서는 기존 수동 입력으로 사용합니다.

Python 소스 실행: `py -3 app.py`. Python 3.11 이상/Tkinter가 필요하며 새 pip 의존성은 없습니다.

## 문서와 검증

- [사용법·보안 경계·검증 범위](PROFILE_FEATURE.md)
- [기존 장비 명령·보고서·복구 가이드](README_STABILIZATION_3.md)
- [승인된 설계](docs/superpowers/specs/2026-11-12-windows-profile-design.md)
- [구현 계획](docs/superpowers/plans/2026-11-12-windows-profile.md)

전체 자동 검사: `py -3 -m unittest discover -s tests -v`

네이티브 Windows DPAPI 검사(합성값·임시 폴더·장비 접속 없음): `py -3 tests/windows_profile_check.py`

Linux에서 전체 332개를 같은 프로세스에서 두 번 실행해 모두 통과했습니다. **Windows EXE 실행·실제 DPAPI 보호·다른 Windows 사용자 접근 및 사내 장비 검증은 미수행**입니다. Windows 검사 스크립트 4개는 Linux 검사 개수에 포함하지 않았습니다. 실행파일은 서명되지 않았습니다.

## 저장 위치와 주의

`%LOCALAPPDATA%\WEC8500_WIPS_Manager\settings\profile.json`

일반 설정과 암호문 블록을 한 파일에서 구분하고, 암호화가 성공한 후 원자적으로 교체합니다. 암호화 실패 시 평문 저장으로 전환하지 않습니다. 모의 실행 상태에서는 저장할 수 없습니다. 다른 컨트롤러/AP 계정·포트로 바꾸면 저장된 암호 사용을 해제하며, 목표 WIPS 서버가 바뀌면 저장된 공유키도 해제합니다.

같은 Windows 사용자 권한의 악성코드까지 보호하지는 못합니다. Telnet 구간 및 기존 공유키 원문 보고서는 별도 관리 대상입니다. 회사의 자격증명 로컬 저장 정책이 허용하는 경우에 사용하세요. 프로그램 삭제/EXE 교체와 저장 프로필 삭제는 별개입니다.
