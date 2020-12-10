import os

import json  # json

import binascii  # hex encoding

import requests  # https requests

from uuid import uuid4  # gen random guid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
# aes + padding, sha256

import webbrowser
import platform
import subprocess
import datetime
import sys

from requests_toolbelt.adapters.fingerprint import FingerprintAdapter


KEYSAVE_PATH = "C:\\ProgramData\\keysave.txt"


class api:
    name = ownerid = secret = ""

    def __init__(self, name, ownerid, secret):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

    session_id = session_iv = ""

    def init(self):
        self.session_iv = str(uuid4())[:8]

        init_iv = SHA256.new(self.session_iv.encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.secret, init_iv)

        if response == "KeyAuth_Disabled":
            print("The program key you tried to use doesn't exist")
            sys.exit()
        if response == "KeyAuth_Initialized":
            print("Initialized")
        else:
            print("The program key you tried to use doesn't exist")
            sys.exit()

    def login(self, key, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        self.session_iv = str(uuid4())[:8]

        init_iv = SHA256.new(self.session_iv.encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "key": encryption.encrypt(key, self.secret, init_iv),
            "hwid": encryption.encrypt(hwid, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.secret, init_iv)

        if response == "KeyAuth_Valid":
            print("Logged in")
        elif response == "KeyAuth_Invalid":
            print("Key not found")
            if os.path.exists(KEYSAVE_PATH):
                os.remove(KEYSAVE_PATH)
                sys.exit()
        elif response == "KeyAuth_InvalidHWID":
            print("This computer doesn't match the computer the key is locked to. If you reset your computer, contact the application owner")
            if os.path.exists(KEYSAVE_PATH):
                os.remove(KEYSAVE_PATH)
                sys.exit()
        elif response == "KeyAuth_Expired":
            print("This key is expired")
            if os.path.exists(KEYSAVE_PATH):
                os.remove(KEYSAVE_PATH)
                sys.exit()
        else:
            print("Application Failed To Connect. Try again or contact application owner")
            if os.path.exists(KEYSAVE_PATH):
                os.remove(KEYSAVE_PATH)
                sys.exit()

    def __do_request(self, post_data):
        headers = {"User-Agent": "KeyAuth"}

        rq_out = requests.post(
            "https://keyauth.com/api/", data=post_data, headers=headers, verify=False
        )

        return rq_out.text


class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return "None"

        cmd = subprocess.Popen(
            "wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

        (suppost_sid, _error) = cmd.communicate()

        suppost_sid = suppost_sid.split(b'\n')[1].strip()

        return suppost_sid.decode()


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid App Secret")
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid App Secret")
            sys.exit()
