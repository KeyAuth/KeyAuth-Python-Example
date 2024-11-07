from os import _exit, system, getenv
from json import loads
from binascii import unhexlify
from .hwid import WINDOWS_HWID
from .req import post as _req_post

class mainapi:
    def __init__(self, name=None, ownerid=None, version=None, hash_to_check=None):
        """
        Initializes the API instance with given parameters.

        :param name: Name of the app.
        :param ownerid: Account ID.
        :param version: Application version.
        :param hash_to_check: Value of MD5 checksum (hash) of a file.
        """
        self.name = name
        self.ownerid = ownerid
        self.version = version
        self.hash_to_check = hash_to_check
        self.initialized = False
        self.init()
    
    def CheckInit_HWID(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            _exit(1)
        return WINDOWS_HWID().main()
        
    def init(self):
        if len(self.ownerid) != 10:
            print(
                "Invalid owner ID length. Visit https://keyauth.cc/app/, copy the Python code, "
                "and replace the code in main.py with that."
            )
            _exit(1)

        post_data = {
            "type": "init",
            "ver": self.version,
            "hash": self.hash_to_check,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data) # response & statusCode in txt from req.py `sever`
        
        if response == "KeyAuth_Invalid":
            print(f"The application doesn't exist ")
            _exit(1)
        
        response_json = loads(response)
        if response_json["message"] == "invalidver":
            if response_json["download"] != "":
                print("New Version Available")
                download_link = response_json["download"]
                system(f"start {download_link}")
                _exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                _exit(1)
        
        if not response_json["success"]:
            print('Something went wrong here !')
            print(f'Response From Server : \n\n{response_json}')
        
        self.initialized = True
        self.sessionid = response_json["sessionid"]

    def fetchStats(self):
        """
        fetch stats return dict of data that include stats
        example total keys, seller panel link, etc
        """
        params = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid}
        response = _req_post(params)
        return loads(response)
    
    def fetchOnline(self):
        """
        fetch number of users online
        """

        self.CheckInit_HWID()
        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json.get("success"):
            return json.get("users") if json.get("users") else None
        else:
            return json


    def log(self, message):
        '''
        Log message to the server and then to your webhook what is set on app settings
        keyauthapp.log("Message")
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "log",
            "pcuser": getenv('username'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        resp = loads(_req_post(post_data))
        resp['message'] = message
        return resp

    def register(self, user, password, license, hwid=None):
        """
        Registering new username & password

        :param user: username to set.
        :param password: password to set.
        :param license: LicenseKey.
        :param hwid: user HWID || You can also use this paramter with SSID.
        """
        sys_hwid = self.CheckInit_HWID()

        post_data = {
            "type": "register",
            "username": user,
            "pass": password,
            "key": license,
            "hwid": sys_hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            print(json["message"])
            return load_user_data(json["info"])
        else:
            print(json["message"])
            return json

    def license(self, key, hwid=None):
        """
        Checking License Key Validity

        :param key: license key using as login.
        :param hwid: user hwid to verify device login.
        """
        sys_hwid = self.CheckInit_HWID()
        post_data = {
            "type": "license",
            "key": key,
            "hwid": sys_hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            print(json["message"])
            return load_user_data(json["info"])
        else:
            print(json["message"])
            return json
    
    def upgrade(self, user, license):
        """
        Upgrading duration of user

        :param user: username.
        :param license: license key.
        """
        self.CheckInit_HWID()

        post_data = {
            "type": "upgrade",
            "username": user,
            "key": license,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)

        json = loads(response)

        if json["success"]:
            print(json["message"])
            print("Please restart program and login")
            return json["message"]
        else:
            print(json["message"])
            return json

    def login(self, user, password, hwid=None):
        """
        login user with username & password

        :param user: username for login.
        :param password: password for login.
        :param hwid: user hwid to verify device login.
        """
        sys_hwid = self.CheckInit_HWID()

        post_data = {
            "type": "login",
            "username": user,
            "pass": password,
            "hwid": sys_hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)

        json = loads(response)

        if json["success"]:
            print(json["message"])
            return load_user_data(json['info'])
        else:
            print(json["message"])
            return json
    
    def var(self, name):
        '''
        Get normal variable and print it
        data = keyauthapp.var("varName")
        '''
        self.CheckInit_HWID()
        post_data = {
            "type": "var",
            "varid": name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)

        json = loads(response)
        if json["success"]:
            print(json['message'])
            return json["message"]
        else:
            print(json["message"])
            return json

    def getvar(self, var_name):
        '''
        Get user variable and print it
        keyauthapp.getvar("varName")
        '''
        self.CheckInit_HWID()
        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)

        json = loads(response)

        if json["success"]:
            print(json['response'])
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            return json

    def setvar(self, var_name, var_data):
        '''
        :param var_name: Name Of Variable.
        :param var_data: data to set on variable data.
        Set up user variable
        keyauthapp.setvar("varName", "varValue")
        '''
        self.CheckInit_HWID()
        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)
        json = loads(response)
        if json["success"]:
            return True
        else:
            print(json["message"])
            return False
    
    def ban(self):
        '''
        Ban the user and blacklist their HWID and IP Address.
        Good function to call upon if you use anti-debug and have detected an intrusion attempt.
        :Note: Function only works after login.
        keyauthapp.ban()
        '''
        self.CheckInit_HWID()
        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)

        json = loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            return False
        
    def file(self, fileid):
        '''
        Download Files form the server to your computer using the download function in the api class
        bytes = keyauthapp.file("385624")
        f = open("example.exe", "wb")
        f.write(bytes)
        f.close()
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "file",
            "fileid": fileid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        print(json)

        if json["success"]:
            print(json)
        else:
            print(json["message"])

        return unhexlify(json["contents"])
    
    def webhook(self, webid, param, body = "", conttype = ""):
        '''
        Log message to the server and then to your webhook what is set on app settings
        keyauthapp.log("Message")
        '''
        
        self.CheckInit_HWID()
        post_data = {
            "type": "webhook",
            "webid": webid,
            "params": param,
            "body": body,
            "conttype": conttype,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            return json
    
    def check(self):
        '''
        Use this to see if the user is logged in or not.
        print(f"Current Session Validation Status: {keyauthapp.check()}")
        '''
        self.CheckInit_HWID()

        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            return True
        else:
            return False
        
    def check_blacklist(self):
        """
        Verifies whether the HWID or IP address is blacklisted.

        This optional check can enhance security by preventing blacklisted users from accessing the program, even for a brief moment. 
        However, for faster performance, you may opt to skip this check and rely on the KeyAuth server to automatically 
        block blacklisted users at login or registration attempts. This function serves as an auxiliary, preemptive security measure.
        """

        hwid = self.CheckInit_HWID()
        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = _req_post(post_data)
        json = loads(response)
        return json['success']
        
    def chatGet(self, channel):
        '''
        Example from the form example on how to fetch the chat messages.

        Get chat messages
        messages = keyauthapp.chatGet("CHANNEL")
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "chatget",
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None
        
    def chatSend(self, message, channel):
        '''
        * Send chat message
        keyauthapp.chatSend("MESSAGE", "CHANNEL")
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "chatsend",
            "message": message,
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            return True
        else:
            return False
        
    def changeUsername(self, username):
        '''
        use this to change username from old -> new, username
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "changeUsername",
            "newUsername": username,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            print("Successfully changed username")
        else:
            print(json["message"])
            return json
        
    def logout(self):
        '''
        Logout the users session and close the application.

        This only works if the user is authenticated (logged in)
        :call func: keyauthapp.logout()
        '''

        self.CheckInit_HWID()
        post_data = {
            "type": "logout",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = _req_post(post_data)
        json = loads(response)

        if json["success"]:
            print("Successfully logged out")
            return json
        else:
            print(json["message"])
            return json      

def load_app_data(data) -> dict:
    '''
    :param data: contain app data.
    this will return a dictonary containing `app data`
    '''
    results: dict = {}
    results.update({
        'users_len': data["numUsers"],
        'keys_len': data["numKeys"],
        'app_version': data["version"],
        'customer_panel': data["customerPanelLink"],
        'active_users': data["numOnlineUsers"],
    })
    return results

def load_user_data(data: dict) -> dict:
    '''
    :param data: contain user data.
    this will also return dictonary which include `user data`
    '''
    results: dict = {}
    results.update({
        'username': data["username"],
        'ip': data["ip"],
        'hwid': data["hwid"] or "N/A",
        'expire': data["subscriptions"][0]["expiry"],
        'create_date': data["createdate"],
        'last_login': data["lastlogin"],
        'subscription': data["subscriptions"][0]["subscription"],
        'subscriptions': data["subscriptions"],
    })
    return results
