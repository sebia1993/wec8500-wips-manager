# WEC8500 WIPS Manager — Windows 보호 프로필 (profile.4)

> **개발·안정화 및 GitHub 배포 100% (9/9단계 완료)** · [진행 현황](STABILIZATION_PROGRESS.md). Windows·사내 실검증은 사용자 별도 수행이며 진행률 산정에서 제외합니다. 현재 `v1.5.1-profile.4` pre-release가 게시되어 있고, 직접 첨부된 배포 파일은 Windows 실행파일 ZIP 1개입니다.

profile.3의 프로필 화면 반영 오류 시 인증정보 혼합을 수정한 누적 검증용 빌드입니다. 새 프로필의 주소와 이전 비밀번호·AP 목록이 섞여 실행되는 경로를 차단했습니다. 새로운 기능은 추가하지 않았습니다.

## 사용

기존 프로그램 창을 모두 종료하고 ZIP 전체를 새 폴더에 풀어 `WEC8500_WIPS_Manager_v1.5.1_profile.4_Win11_x64.exe`를 실행합니다. 기존 저장 형식과 사용자별 저장 위치는 그대로입니다.

처음에는 모의 실행을 해제하고 기본 설정을 입력한 뒤 **설정 저장**에서 AP 비밀번호·목표 공유키·AP 목록 저장 여부를 각각 선택합니다. 이후 실행에서는 저장 설정을 불러오고 WEC8500 ID·비밀번호를 입력한 다음 AP 대상을 확인하고 기존 작업 버튼을 사용합니다. **WEC8500 ID·비밀번호는 저장하지 않으며 자동 접속·자동 변경도 하지 않습니다.**

불러오는 도중 화면 갱신 오류가 나면 새 프로필을 사용 가능 상태로 확정하지 않습니다. 일부 일반 입력값이 남을 수 있으므로 다시 불러오기 완료 여부와 대상 목록을 확인하세요. 저장 파일과 이전 작업 결과·이어하기 정보는 그대로 보존됩니다.

저장 위치: `%LOCALAPPDATA%\WEC8500_WIPS_Manager\settings\profile.json`

## 문서와 검사

- [이번 불러오기 안정화 및 검증 범위](PROFILE_LOAD_STABILITY.md)
- [profile.3 종료 확인창 경합 수정](PROFILE_MODAL_STABILITY.md)
- [profile.2 저장 충돌 방지·화면 응답 개선](PROFILE_STABILITY.md)
- [기본 저장 기능 사용법](PROFILE_FEATURE.md)
- [기존 장비 명령·보고서·복구 가이드](README_STABILIZATION_3.md)

소스 실행: `py -3 app.py` (Python 3.11 이상/Tkinter, 새 pip 의존성 없음).
전체 검사: `py -3 -m unittest discover -s tests -v`.
Windows 별도 검사: `py -3 tests/windows_profile_check.py` (합성값·임시 폴더, 장비 접속 없음).

릴리스 준비 과정에서 Linux/Xvfb의 전체 424개 회귀 검사를 실행해 실패·오류·건너뜀 없이 통과했습니다. 누적 변경 및 검증 범위는 RELEASE_NOTES_PROFILE4.md를 참고하세요. **Windows EXE·네이티브 DPAPI/잠금/권한/확인창·사내 장비 검증은 사용자 별도 확인 범위**이며 실행파일은 서명되지 않았습니다. 기존 X11 전용 검사 6개는 Windows/macOS에서 건너뛰고 Windows 별도 검사 6개는 위 실행 수에 포함하지 않습니다.

기존 `.profile.lock`은 실행 중 삭제하지 마세요. `PROFILE_CHANGED`는 최신 설정을 불러온 뒤 다시 확인하고, `PROFILE_BUSY`는 다른 창의 설정 처리가 끝난 뒤 재시도하세요. 이어하기는 이전 실행의 인증정보와 목표를 유지합니다.

현재 Windows 사용자 권한의 악성코드까지 차단하는 앱 전용 금고는 아닙니다. Telnet 구간과 조회 공유키 원문 보고서는 별도 관리 대상이며 사내 저장 정책을 따라 사용하세요.

## 릴리스 상태

`v1.5.1-profile.4` pre-release가 게시되어 있습니다. **직접 첨부된 배포 파일은 `WEC8500_WIPS_Manager_v1.5.1_profile.4_Win11_x64.zip` 1개만 유지합니다.** GitHub 화면의 Source code (zip) / Source code (tar.gz)는 태그에서 자동 생성되는 항목입니다.

사내 검증은 이 배포 작업의 완료 조건에 포함하지 않으며, 사용자 환경에서 발견되는 문제는 별도 안정화 피드백으로 처리합니다.
