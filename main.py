from keyauth import api

import os
import os.path
import platform
from datetime import datetime

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

keyauthapp = api("app name here", "owner id here", "app secret here","1.0")

print("Initializing")
keyauthapp.init()

print ("""
1.Login
2.Register
3.Upgrade
4.License Key Only
""")
ans=input("Select Option: ") 
if ans=="1": 
    user = input('Provide username: ')
    password = input('Provide password: ')
    keyauthapp.login(user,password)
elif ans=="2":
    user = input('Provide username: ')
    password = input('Provide password: ')
    license = input('Provide License: ')
    keyauthapp.register(user,password,license) 
elif ans=="3":
    user = input('Provide username: ')
    license = input('Provide License: ')
    keyauthapp.upgrade(user,license)
elif ans=="4":
    key = input('Enter your license: ')
    keyauthapp.license(key)
elif ans !="":
  print("\n Not Valid Option") 

print("\n User data: ") 
print(" Username: " + keyauthapp.user_data.username)
print(" IP address: " + keyauthapp.user_data.ip)
print(" Hardware-Id: " + keyauthapp.user_data.hwid)
print(" Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print(" Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print(" Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))