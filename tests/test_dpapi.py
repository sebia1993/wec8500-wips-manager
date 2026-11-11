"""Win32 FFI contract checks; NOT native Windows encryption validation."""
import ctypes as C
import sys
import unittest
from unittest.mock import patch

from wec_wips.dpapi import DpapiProtector, ProtectionError, DATA_BLOB


class Function:
    def __init__(self, call):self.call=call
    def __call__(self,*args):return self.call(*args)


class Api:
    def __init__(self, success=True):
        self.success=success;self.calls=[];self.freed=[];self.allocated=[]
        self.CryptProtectData=Function(lambda *a:self.crypt(False,*a))
        self.CryptUnprotectData=Function(lambda *a:self.crypt(True,*a))
        self.LocalFree=Function(self.free)
    def crypt(self,decrypt,src,desc,entropy,reserved,prompt,flags,out):
        inp=C.cast(src,C.POINTER(DATA_BLOB)).contents
        extra=C.cast(entropy,C.POINTER(DATA_BLOB)).contents
        self.calls.append(dict(decrypt=decrypt,data=C.string_at(inp.pbData,inp.cbData),
                               entropy=C.string_at(extra.pbData,extra.cbData),flags=flags,
                               description=desc,reserved=reserved,prompt=prompt))
        data=b'fake-plaintext' if decrypt else b'fake-ciphertext'
        buf=C.create_string_buffer(data,len(data));self.allocated.append(buf)
        dest=C.cast(out,C.POINTER(DATA_BLOB)).contents
        dest.cbData=len(data);dest.pbData=C.cast(buf,C.POINTER(C.c_ubyte))
        return int(self.success)
    def free(self,pointer):self.freed.append(pointer.value);return None


class DpapiContractTests(unittest.TestCase):
    def run_native_contract(self,api,action):
        with patch('wec_wips.dpapi.sys.platform','win32'),patch.object(C,'WinDLL',create=True,return_value=api) as load:
            value=action()
        self.assertEqual([c.args[0] for c in load.call_args_list],['crypt32.dll','kernel32.dll'])
        self.assertTrue(all(c.kwargs['winmode']==0x800 for c in load.call_args_list))
        return value

    def test_protect_calls_current_user_dpapi_no_machine_flag(self):
        api=Api();out=self.run_native_contract(api,lambda:DpapiProtector().protect(b'abc\x00xyz',b'context'))
        self.assertEqual(out,b'fake-ciphertext');call=api.calls[0]
        self.assertEqual(call['data'],b'abc\x00xyz');self.assertEqual(call['entropy'],b'context')
        self.assertEqual(call['flags'],1);self.assertFalse(call['flags'] & 4)
        self.assertIsNone(call['prompt']);self.assertIsNone(call['reserved'])
        self.assertEqual(len(api.freed),1)
        self.assertEqual(bytes(api.allocated[0]),b'\x00'*len(b'fake-ciphertext'))

    def test_unprotect_does_not_request_description_or_prompt(self):
        api=Api();out=self.run_native_contract(api,lambda:DpapiProtector().unprotect(b'blob',b'context'))
        self.assertEqual(out,b'fake-plaintext');call=api.calls[0]
        self.assertTrue(call['decrypt']);self.assertIsNone(call['description'])
        self.assertEqual(call['flags'],1);self.assertEqual(len(api.freed),1)
        self.assertEqual(bytes(api.allocated[0]),b'\x00'*len(b'fake-plaintext'))

    def test_failed_api_releases_output_and_exposes_fixed_error(self):
        api=Api(success=False)
        with patch('wec_wips.dpapi.sys.platform','win32'),patch.object(C,'WinDLL',create=True,return_value=api):
            with self.assertRaises(ProtectionError) as err:DpapiProtector().unprotect(b'SECRET_ERROR',b'context')
        self.assertEqual(len(api.freed),1);self.assertNotIn('SECRET_ERROR',str(err.exception))

    def test_unsupported_platform_never_falls_back_to_plaintext(self):
        with patch('wec_wips.dpapi.sys.platform','linux'):
            for fn in (DpapiProtector().protect,DpapiProtector().unprotect):
                with self.assertRaises(ProtectionError):fn(b'data',b'context')

    def test_dll_failure_is_sanitized(self):
        with patch('wec_wips.dpapi.sys.platform','win32'),patch.object(C,'WinDLL',create=True,side_effect=OSError('PRIVATE_PATH_SECRET')):
            with self.assertRaises(ProtectionError) as err:DpapiProtector().protect(b'data',b'context')
        self.assertNotIn('PRIVATE_PATH_SECRET',str(err.exception))

    def test_input_limits_are_checked_before_loading_dll(self):
        with patch('wec_wips.dpapi.sys.platform','win32'),patch.object(C,'WinDLL',create=True) as load:
            for data,entropy in ((b'',b'x'),(b'x',b''),(b'x'*131073,b'e'),('text',b'e')):
                with self.assertRaises(ProtectionError):DpapiProtector().protect(data,entropy)
        load.assert_not_called()

if __name__=='__main__':unittest.main()
