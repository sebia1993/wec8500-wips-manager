"""Current-user Windows DPAPI. No machine scope, key files or plaintext fallback."""
from __future__ import annotations

import ctypes as C
import sys


class ProtectionError(RuntimeError):
    """Fixed messages only; underlying errors may contain sensitive data."""


class DATA_BLOB(C.Structure):
    _fields_ = [('cbData', C.c_uint32), ('pbData', C.POINTER(C.c_ubyte))]


class DpapiProtector:
    MAX_DATA = 128 * 1024

    def protect(self, data: bytes, entropy: bytes) -> bytes:
        return self._crypt(data, entropy, False)

    def unprotect(self, data: bytes, entropy: bytes) -> bytes:
        return self._crypt(data, entropy, True)

    def _crypt(self, data, entropy, decrypt):
        if sys.platform != 'win32':
            raise ProtectionError('암호화 저장은 Windows 사용자 환경에서만 사용할 수 있습니다.')
        if (not isinstance(data, bytes) or not 1 <= len(data) <= self.MAX_DATA
                or not isinstance(entropy, bytes) or not 1 <= len(entropy) <= 4096):
            raise ProtectionError('보호할 데이터 형식을 확인할 수 없습니다.')
        output = DATA_BLOB()
        in_buffer = entropy_buffer = None
        kernel = None
        try:
            # Load only system DLLs, never a same-named file beside the EXE.
            crypt = C.WinDLL('crypt32.dll', use_last_error=True, winmode=0x00000800)
            kernel = C.WinDLL('kernel32.dll', use_last_error=True, winmode=0x00000800)
            blob_ptr = C.POINTER(DATA_BLOB)
            crypt.CryptProtectData.argtypes = [blob_ptr, C.c_wchar_p, blob_ptr,
                                               C.c_void_p, C.c_void_p, C.c_uint32, blob_ptr]
            crypt.CryptProtectData.restype = C.c_int
            crypt.CryptUnprotectData.argtypes = [blob_ptr, C.c_void_p, blob_ptr,
                                                 C.c_void_p, C.c_void_p, C.c_uint32, blob_ptr]
            crypt.CryptUnprotectData.restype = C.c_int
            kernel.LocalFree.argtypes = [C.c_void_p]
            kernel.LocalFree.restype = C.c_void_p
            in_buffer = C.create_string_buffer(data, len(data))
            entropy_buffer = C.create_string_buffer(entropy, len(entropy))
            source = DATA_BLOB(len(data), C.cast(in_buffer, C.POINTER(C.c_ubyte)))
            extra = DATA_BLOB(len(entropy), C.cast(entropy_buffer, C.POINTER(C.c_ubyte)))
            function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
            description = None if decrypt else 'WEC8500 WIPS Manager profile v1'
            # 0x1 = CRYPTPROTECT_UI_FORBIDDEN. 0x4 LOCAL_MACHINE is deliberately absent.
            ok = function(C.byref(source), description, C.byref(extra), None, None, 0x1, C.byref(output))
            if not ok or not output.pbData or not 1 <= output.cbData <= self.MAX_DATA:
                raise ProtectionError('Windows 사용자 보호 데이터를 처리하지 못했습니다.')
            return C.string_at(output.pbData, output.cbData)
        except Exception:
            raise ProtectionError('Windows 사용자 보호 데이터를 처리하지 못했습니다. 다시 입력해 주세요.') from None
        finally:
            # Best effort only: Python strings/bytes and OS memory are not fully erasable.
            if in_buffer is not None:
                C.memset(in_buffer, 0, len(in_buffer))
            if entropy_buffer is not None:
                C.memset(entropy_buffer, 0, len(entropy_buffer))
            if output.pbData and kernel is not None:
                if 0 < output.cbData <= self.MAX_DATA:
                    C.memset(output.pbData, 0, output.cbData)
                kernel.LocalFree(C.cast(output.pbData, C.c_void_p))
