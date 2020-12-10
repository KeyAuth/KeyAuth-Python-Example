from keyauth import api

import os
import os.path

keyauthapp = api("your app name here", "your ownerid here", "your app secret here")

print("Initializing")
keyauthapp.init()

if os.path.exists(file_path):
    with open ("C:\\ProgramData\\keysave.txt", "r") as file:
    data=file.readlines()
    keyauthapp.login(data)
else:
    _key = input('Enter your key: ')
    keyauthapp.login(_key)

keysave = open("C:\\ProgramData\\keysave.txt", "w")
n = keysave.write(_key)
keysave.close()
