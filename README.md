# WEC8500 WIPS Manager — Windows 보호 프로필 (profile.3)

profile.2의 종료 확인창 경합을 수정한 누적 검증용 빌드입니다. **종료 여부를 선택하기 전에 준비된 장비 작업이 시작되는 문제**를 차단했습니다. 기존 프로필 저장·충돌 방지·암호화·장비 작업 기능은 유지합니다.

## 사용

기존 프로그램 창을 모두 종료하고 ZIP 전체를 새 폴더에 풀어 `WEC8500_WIPS_Manager_v1.5.1_profile.3_Win11_x64.exe`를 실행합니다. 저장 형식과 사용자별 저장 위치는 바꾸지 않았습니다.

처음에는 모의 실행을 해제하고 기본 설정을 입력한 뒤 **설정 저장**에서 AP 비밀번호·목표 공유키·AP 목록 저장 여부를 각각 선택합니다. 이후 실행에서 저장 설정을 불러오고 WEC8500 ID·비밀번호를 입력한 다음 대상을 확인하고 기존 작업 버튼을 누릅니다. **WEC8500 사용자 ID·비밀번호는 저장하지 않으며 자동 접속·자동 변경은 하지 않습니다.**

비밀 입력창이 비어 있으면 체크된 저장 값을 사용하고 직접 입력한 값이 우선합니다. 실제 조회 전용 작업은 저장된 목표 공유키를 복호화하지 않습니다. 저장된 값 변경은 명시적인 설정 저장으로만 반영합니다. 같은 창의 이어하기는 이전 실행의 인증정보와 목표를 유지합니다.

저장 위치: `%LOCALAPPDATA%\WEC8500_WIPS_Manager\settings\profile.json`

## 문서

- [이번 종료 경합 수정 및 검증 범위](PROFILE_MODAL_STABILITY.md)
- [profile.2 저장 충돌 방지·화면 응답 개선](PROFILE_STABILITY.md)
- [기본 프로필 사용법·보안 경계](PROFILE_FEATURE.md)
- [기존 장비 명령·보고서·복구 가이드](README_STABILIZATION_3.md)

소스 실행: `py -3 app.py` (Python 3.11 이상과 Tkinter, 새 pip 의존성 없음).
전체 검사: `py -3 -m unittest discover -s tests -v`.
Windows 보호기 검사: `py -3 tests/windows_profile_check.py` (합성값·임시 폴더만 사용).

Linux/Xvfb에서 378개 기준 검사에 종료 확인창 경계 검사 6개를 추가한 전체 384개를 두 번 실행해 통과했습니다. 새 확인창 자동 조작 검사는 X11 전용이므로 Windows/macOS에서는 건너뜁니다. **Windows EXE·네이티브 확인창·DPAPI·잠금·권한·사내 장비는 미검증**이며 실행파일은 서명되지 않았습니다.

기존 `.profile.lock`은 비밀정보 없는 빈 잠금 파일이며 실행 중 삭제하지 마세요. `PROFILE_CHANGED`는 최신 설정을 불러온 뒤 다시 확인하고, `PROFILE_BUSY`는 다른 창의 설정 처리가 끝난 뒤 다시 시도하세요.

동일 Windows 사용자 권한의 악성코드까지 보호하는 앱 전용 금고는 아닙니다. 기존 Telnet 구간과 조회 공유키 원문이 포함된 HTML·CSV·TXT 보고서는 별도 관리 대상입니다. 사내 저장 정책이 허용하는 환경에서 사용하세요.
