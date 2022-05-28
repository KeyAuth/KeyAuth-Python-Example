from keyauth import api
import os
import sys
import os.path
import platform
import hashlib
from time import sleep
from datetime import datetime

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA
os.system("cls")
os.system("title Python Example")
print("Initializing")
def getchecksum():
    path = os.path.basename(__file__)
    if not os.path.exists(path):
    	path = path[:-2] + "exe"
    md5_hash = hashlib.md5()
    a_file = open(path,"rb")
    content = a_file.read()
    md5_hash.update(content)
    digest = md5_hash.hexdigest()
    return digest

keyauthapp = api(
	name = "",
	ownerid = "",
	secret = "",
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
print(f"Blacklisted? : {keyauthapp.checkblacklist()}") # check if blacklisted, you can edit this and make it exit the program if blacklisted
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
else:
	print("\nNot Valid Option") 
	sys.exit()


#region Extra Functions

#* Download Files form the server to your computer using the download function in the api class
#bytes = keyauthapp.download("FILEID")
#f = open("example.exe", "wb")
#f.write(bytes)
#f.close()


#* Set up user variable
#keyauthapp.setvar("varName", "varValue")

#* Get user variable and print it
#data = keyauthapp.getvar("varName")
#print(data)

#* Get normal variable and print it
#data = keyauthapp.var("varName")
#print(data)

#* Log message to the server and then to your webhook what is set on app settings
#keyauthapp.log("Message")

#* Get if the user pc have been blacklisted
#print(f"Blacklisted? : {keyauthapp.checkblacklist()}")

#* See if the current session is validated
#print(f"Session Validated?: {keyauthapp.check()}")


#* example to send normal request with no POST data
#data = keyauthapp.webhook("WebhookID", "?type=resetuser&user=username")

#endregion

print("\nUser data: ") 
print("Username: " + keyauthapp.user_data.username)
print("IP address: " + keyauthapp.user_data.ip)
print("Hardware-Id: " + keyauthapp.user_data.hwid)
#print("Subcription: " + keyauthapp.user_data.subscription) ## Print Subscription "ONE" name

subs = keyauthapp.user_data.subscriptions ## Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
  sub = subs[i]["subscription"] # Subscription from every Sub
  expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime('%Y-%m-%d %H:%M:%S') ## Expiry date from every Sub
  timeleft = subs[i]["timeleft"] ## Timeleft from every Sub

  print(f"[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")


print("Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print("Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print("Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"Current Session Validation Status: {keyauthapp.check()}")
print("Exiting in 10 secs....")
sleep(10)
exit(0)