from keyauth import api

import os
import os.path

KEYSAVE_PATH = "C:\\ProgramData\\keysave.txt"

keyauthapp = api("your app name here", "your ownerid here", "your app secret here")

print("Initializing")
keyauthapp.init()

if os.path.exists(KEYSAVE_PATH):
    with open (KEYSAVE_PATH, "r") as file:
        data = file.readline()
    keyauthapp.login(data)
else:
    key = input('Enter your key: ')
    keyauthapp.login(key)
    keysave = open(KEYSAVE_PATH, "w")
    n = keysave.write(key)
    keysave.close()
