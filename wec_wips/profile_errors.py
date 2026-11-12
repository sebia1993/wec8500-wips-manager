"""Non-sensitive profile failure classifications; never include OS exception text."""
_MESSAGES = {
    'PROFILE_CHANGED': '다른 창에서 저장 설정이 변경되거나 삭제되었습니다. 최신 설정을 불러온 뒤 다시 진행하세요.',
    'PROFILE_BUSY': '다른 창에서 저장 설정을 처리하고 있습니다. 잠시 후 다시 진행하세요.',
    'PROFILE_ACCESS_DENIED': '저장 설정에 접근할 수 없습니다. 사용자 권한과 파일 사용 상태를 확인하세요.',
    'PROFILE_READ_FAILED': '저장 설정을 읽지 못했습니다. 기존 파일은 보존됩니다.',
    'PROFILE_FORMAT_INVALID': '저장 설정의 형식이 올바르지 않습니다. 파일은 보존됩니다. 수동 입력하거나 명시적으로 삭제 후 다시 저장하세요.',
    'PROFILE_DECRYPT_FAILED': '저장된 비밀정보를 복호화하지 못했습니다. Windows 사용자 환경을 확인하고 직접 입력하세요.',
    'PROFILE_PROTECT_FAILED': 'Windows 암호화에 실패하여 저장하지 않았습니다. 기존 설정은 유지됩니다.',
    'PROFILE_WRITE_FAILED': '설정 저장에 실패했습니다. 권한·저장 공간을 확인하세요. 기존 설정은 유지됩니다.',
    'PROFILE_DELETE_FAILED': '설정을 삭제하지 못했습니다. 파일 사용 상태와 권한을 확인하세요.',
    'PROFILE_WORKER_FAILED': '설정 처리를 완료하지 못했습니다. 저장 상태를 확인하고 다시 진행하세요.',
    'PROFILE_INVALID_INPUT': '프로필 입력값을 확인하세요.',
}


class ProfileError(ValueError):
    """Only fixed application messages may cross a worker/UI boundary."""
    def __init__(self, message=None, *, code='PROFILE_INVALID_INPUT'):
        self.code = code if code in _MESSAGES else 'PROFILE_WORKER_FAILED'
        self.message = message or _MESSAGES[self.code]
        super().__init__(f'[{self.code}] {self.message}')
