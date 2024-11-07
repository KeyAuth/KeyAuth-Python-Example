from platform import system
from os import getlogin
from subprocess import Popen, PIPE
import ctypes
from ctypes.wintypes import DWORD

class WINDOWS_HWID:
    def main(self):
        if system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid # return hwid for linux
            
        elif system() == 'Windows':
            return self.get_hwid() # return hwid for window
        
        elif system() == 'Darwin':
            output = Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid # return hwid for darwin os

    def get_hwid(self):
        winuser = getlogin()
        # sid = self.hwid_sid_ctype(winuser, 'sid')
        hwid = self.hwid_sid_ctype(winuser, 'hwid')

        return hwid
    
    def hwid_sid_ctype(self, win_usr, key=''):
        if key == 'hwid':
            return self.sid_2_Str_sid(self.acc_lkup(None, win_usr))
        else:
            sid = "PySID:"+self.sid_2_Str_sid(self.acc_lkup(None, win_usr))
            return sid   
    
    def acc_lkup(self,system, account_name):
        MAX_DOMAIN = 256
        domain_name_buf = ctypes.create_unicode_buffer(MAX_DOMAIN)
        sid = ctypes.create_string_buffer(256)
        sid_size = ctypes.c_ulong(256)
        domain_size = ctypes.c_ulong(MAX_DOMAIN)
        use = DWORD()
        result = ctypes.windll.advapi32.LookupAccountNameW(
            system,
            account_name,
            sid,
            ctypes.byref(sid_size),
            domain_name_buf,
            ctypes.byref(domain_size),
            ctypes.byref(use)
        )
        if not result:
            raise WindowsError(ctypes.GetLastError())
        return sid.raw

    def sid_2_Str_sid(self, sid):
        string_sid = ctypes.c_wchar_p()
        result = ctypes.windll.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(string_sid))
        if not result:
            raise WindowsError(ctypes.GetLastError())
        return string_sid.value
    
# data = WINDOWS_HWID().main()
# print(data)