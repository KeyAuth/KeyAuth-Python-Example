from keyauth import api

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime

# import json as jsond
# ^^ only for auto login/json writing/reading

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

if sys.version_info.minor < 10:  # Python version check (Bypass Patch)
    print("[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+")
    print("You are using Python {}.{}".format(sys.version_info.major, sys.version_info.minor))

if platform.system() == 'Windows':
    os.system('cls & title Python Example')  # clear console, change title
elif platform.system() == 'Linux':
    os.system('clear')  # clear console
    sys.stdout.write("\x1b]0;Python Example\x07")  # change title
elif platform.system() == 'Darwin':
    os.system("clear && printf '\e[3J'")  # clear console
    os.system('''echo - n - e "\033]0;Python Example\007"''')  # change title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "", #App name (Manage Applications --> Application name)
    ownerid = "", #Owner ID (Account-Settings --> OwnerID)
    secret = "", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)

print(f"""
App data:
Number of users: {keyauthapp.app_data.numUsers}
Number of online users: {keyauthapp.app_data.onlineUsers}
Number of keys: {keyauthapp.app_data.numKeys}
Application Version: {keyauthapp.app_data.app_ver}
Customer panel link: {keyauthapp.app_data.customer_panel}
""")
print(f"Current Session Validation Status: {keyauthapp.check()}")
print(f"Blacklisted? : {keyauthapp.checkblacklist()}")  # check if blacklisted, you can edit this and make it exit the program if blacklisted


def answer():
    try:
        print("""
1.Login
2.Register
3.Upgrade
4.License Key Only
        """)
        ans = input("Select Option: ")
        if ans == "1":
            user = input('Provide username: ')
            password = input('Provide password: ')
            keyauthapp.login(user, password)
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
            keyauthapp.license(key)
        else:
            print("\nNot Valid Option")
            time.sleep(1)
            os.system('cls')
            answer()
    except KeyboardInterrupt:
        os._exit(1)


answer()

# region Extra Functions

# * Download Files form the server to your computer using the download function in the api class
# bytes = keyauthapp.file("FILEID")
# f = open("example.exe", "wb")
# f.write(bytes)
# f.close()


# * Set up user variable
# keyauthapp.setvar("varName", "varValue")

# * Get user variable and print it
# data = keyauthapp.getvar("varName")
# print(data)

# * Get normal variable and print it
# data = keyauthapp.var("varName")
# print(data)

# * Log message to the server and then to your webhook what is set on app settings
# keyauthapp.log("Message")

# * Get if the user pc have been blacklisted
# print(f"Blacklisted? : {keyauthapp.checkblacklist()}")

# * See if the current session is validated
# print(f"Session Validated?: {keyauthapp.check()}")


# * example to send normal request with no POST data
# data = keyauthapp.webhook("WebhookID", "?type=resetuser&user=username")

# * example to send form data
# data = keyauthapp.webhook("WebhookID", "", "type=init&name=test&ownerid=j9Gj0FTemM", "application/x-www-form-urlencoded")

# * example to send JSON
# data = keyauthapp.webhook("WebhookID", "", "{\"content\": \"webhook message here\",\"embeds\": null}", "application/json")

# * Get chat messages
# messages = keyauthapp.chatGet("CHANNEL")

# Messages = ""
# for i in range(len(messages)):
# Messages += datetime.utcfromtimestamp(int(messages[i]["timestamp"])).strftime('%Y-%m-%d %H:%M:%S') + " - " + messages[i]["author"] + ": " + messages[i]["message"] + "\n"

# print("\n\n" + Messages)

# * Send chat message
# keyauthapp.chatSend("MESSAGE", "CHANNEL")

# * Add Application Information to Title
# os.system(f"cls & title KeyAuth Python Example - Total Users: {keyauthapp.app_data.numUsers} - Online Users: {keyauthapp.app_data.onlineUsers} - Total Keys: {keyauthapp.app_data.numKeys}")

# * Auto-Login Example (THIS IS JUST AN EXAMPLE --> YOU WILL HAVE TO EDIT THE CODE PROBABLY)
# 1. Checking and Reading JSON

#### Note: Remove the ''' on line 151 and 226

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

# endregion


print("\nUser data: ")
print("Username: " + keyauthapp.user_data.username)
print("IP address: " + keyauthapp.user_data.ip)
print("Hardware-Id: " + keyauthapp.user_data.hwid)
# print("Subcription: " + keyauthapp.user_data.subscription) ## Print Subscription "ONE" name

subs = keyauthapp.user_data.subscriptions  # Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
    sub = subs[i]["subscription"]  # Subscription from every Sub
    expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
        '%Y-%m-%d %H:%M:%S')  # Expiry date from every Sub
    timeleft = subs[i]["timeleft"]  # Timeleft from every Sub

    print(f"[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")

onlineUsers = keyauthapp.fetchOnline()
OU = ""  # KEEP THIS EMPTY FOR NOW, THIS WILL BE USED TO CREATE ONLINE USER STRING.
if onlineUsers is None:
    OU = "No online users"
else:
    for i in range(len(onlineUsers)):
        OU += onlineUsers[i]["credential"] + " "

print("\n" + OU + "\n")

print("Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print("Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print("Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"Current Session Validation Status: {keyauthapp.check()}")
print("Exiting in 10 secs....")
sleep(10)
os._exit(1)
