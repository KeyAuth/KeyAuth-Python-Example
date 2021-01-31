import json as jsond  # json

import binascii  # hex encoding

import requests  # https requests

from uuid import uuid4  # gen random guid

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
# aes + padding, sha256

import webbrowser, platform, subprocess, datetime, datetime, sys, os

from requests_toolbelt.adapters.fingerprint import FingerprintAdapter

if platform.system() == "Windows":
    KEYSAVE_PATH = "C:\\ProgramData\\keysave.txt"
else:
    KEYSAVE_PATH = "/usr/keysave.txt"


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

        if response == "program_doesnt_exist":
            print("The application doesnt exist")
            sys.exit()

        response = encryption.decrypt(response, self.secret, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            sys.exit()

    def login(self, key, hwid=None):
        if hwid is None: hwid = others.get_hwid()
        
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

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            if os.path.exists(KEYSAVE_PATH):
                os.remove(KEYSAVE_PATH)
            sys.exit()

    def __do_request(self, post_data):
        headers = {"User-Agent": "KeyAuth"}

        rq_out = requests.post(
            "https://keyauth.com/api/v2/", data=post_data, headers=headers, verify="keyauth.pem"
        )

        return rq_out.text

    # region user_data
    class user_data_class:
        key = ""
        expiry = datetime.datetime.now()
        level = 0

    user_data = user_data_class()

    def __load_user_data(self, data):
        self.user_data.key = data["key"]

        self.user_data.expiry = datetime.datetime.fromtimestamp(int(data["expiry"]))

        self.user_data.level = data["level"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return "None"

        cmd = subprocess.Popen("wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

        (suppost_sid, error) = cmd.communicate()

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
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()
