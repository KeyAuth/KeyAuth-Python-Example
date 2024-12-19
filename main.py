'''
KeyAuth.cc Python Example

Go to https://keyauth.cc/app/ and click the Python tab. Copy that code and replace the existing keyauthapp instance in this file.

If you get an error saying it can't find module KeyAuth, try following this https://github.com/KeyAuth/KeyAuth-Python-Example#how-to-compile

If that doesn't work for you, you can paste the contents of KeyAuth.py ABOVE this comment and then remove the "from keyauth import api" and that should work too.

READ HERE TO LEARN ABOUT KEYAUTH FUNCTIONS https://github.com/KeyAuth/KeyAuth-Python-Example#keyauthapp-instance-definition
'''
from keyauth import api

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime, UTC

# import json as jsond
# ^^ only for auto login/json writing/reading

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

def clear():
    if platform.system() == 'Windows':
        os.system('cls & title Python Example')  # clear console, change title
    elif platform.system() == 'Linux':
        os.system('clear')  # Clear the terminal
        sys.stdout.write("\033]0;Python Example\007")  # Set terminal title
        sys.stdout.flush() 
    elif platform.system() == 'Darwin':
        os.system("clear && printf '\033[3J'")  # Clear terminal and scrollback
        os.system('echo -n -e "\033]0;Python Example\007"')  # Set terminal title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "", # App name 
    ownerid = "", # Account ID
    version = "", # Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
    hash_to_check = getchecksum()
)

def answer():
    try:
        print("""1.Login
2.Register
3.Upgrade
4.License Key Only
        """)
        ans = input("Select Option: ")
        if ans == "1":
            user = input('Provide username: ')
            password = input('Provide password: ')
            code = input('Enter 2fa code: (not using 2fa? Just press enter)')
            keyauthapp.login(user, password, code)
        elif ans == "2":
            user = input('Provide username: ')
            password = input('Provide password: ')
            license = input('Provide License: ')
            keyauthapp.register(user, password, license)
        elif ans == "3":
            user = input('Provide username: ')
            license = input('Provide License: ')
            keyauthapp.upgrade(user, license)
        elif ans == "4":
            key = input('Enter your license: ')
            code = input('Enter 2fa code: (not using 2fa? Just press enter)')
            keyauthapp.license(key, code)
        else:
            print("\nInvalid option")
            sleep(1)
            clear()
            answer()
    except KeyboardInterrupt:
        os._exit(1)


answer()

'''try:
    if os.path.isfile('auth.json'): #Checking if the auth file exist
        if jsond.load(open("auth.json"))["authusername"] == "": #Checks if the authusername is empty or not
            print("""
1. Login
2. Register
            """)
            ans=input("Select Option: ")  #Skipping auto-login bc auth file is empty
            if ans=="1": 
                user = input('Provide username: ')
                password = input('Provide password: ')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = input('Provide password: ')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license) 
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        else:
            try: #2. Auto login
                with open('auth.json', 'r') as f:
                    authfile = jsond.load(f)
                    authuser = authfile.get('authusername')
                    authpass = authfile.get('authpassword')
                    keyauthapp.login(authuser,authpass)
            except Exception as e: #Error stuff
                print(e)
    else: #Creating auth file bc its missing
        try:
            f = open("auth.json", "a") #Writing content
            f.write("""{
    "authusername": "",
    "authpassword": ""
}""")
            f.close()
            print ("""
1. Login
2. Register
            """)#Again skipping auto-login bc the file is empty/missing
            ans=input("Select Option: ") 
            if ans=="1": 
                user = input('Provide username: ')
                password = input('Provide password: ')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = input('Provide password: ')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        except Exception as e: #Error stuff
            print(e)
            os._exit(1) 
except Exception as e: #Error stuff
    print(e)
    os._exit(1)'''

keyauthapp.fetchStats()
# Display Application Data
print("\nApplication data: ")
print("App Version: " + keyauthapp.app_data.app_ver)
print("Customer Panel Link: " + keyauthapp.app_data.customer_panel)
print("Number of Keys: " + keyauthapp.app_data.numKeys)
print("Number of Users: " + keyauthapp.app_data.numUsers)
print("Online Users: " + keyauthapp.app_data.onlineUsers)

# Display User Data
print("\nUser data: ")
print("Username: " + keyauthapp.user_data.username)
print("IP address: " + keyauthapp.user_data.ip)
print("Hardware-Id: " + keyauthapp.user_data.hwid)

subs = keyauthapp.user_data.subscriptions  # Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
    sub = subs[i]["subscription"]  # Subscription from every Sub
    expiry = datetime.fromtimestamp(int(subs[i]["expiry"]), UTC).strftime(
        '%Y-%m-%d %H:%M:%S')  # Expiry date from every Sub
    timeleft = subs[i]["timeleft"]  # Timeleft from every Sub

    print(f"[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")

print("Created at: " + datetime.fromtimestamp(int(keyauthapp.user_data.createdate), UTC).strftime('%Y-%m-%d %H:%M:%S'))
print("Last login at: " + datetime.fromtimestamp(int(keyauthapp.user_data.lastlogin), UTC).strftime('%Y-%m-%d %H:%M:%S'))
print("Expires at: " + datetime.fromtimestamp(int(keyauthapp.user_data.expires), UTC).strftime('%Y-%m-%d %H:%M:%S'))

# Two Factor Authentication
print("\nTwo Factor Authentication:")
print("1. Enable 2FA")
print("2. Disable 2FA")

tfaans = input("Select Option: ")
if tfaans == "1":
    keyauthapp.enable2fa()  # You only need to call this once as it's called in the API file. 
elif tfaans == "2":
    keyauthapp.disable2fa()  # You only need to call this once as it's called in the API file, and should ideally only need to be called once anyways. 
else:
    print("\nInvalid Option")

print("\nExiting in five seconds..")
sleep(5)
os._exit(1)
