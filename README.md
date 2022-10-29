# KeyAuth-Python-Example
KeyAuth Python Example For The https://keyauth.cc Authentication system.

**What is KeyAuth?**

KeyAuth is an Open source authentication system with cloud hosting plans as well. Client SDKs available for C++, C#, Python, Rust, PHP, JS, GO, Ruby and VB.NET. KeyAuth has several unique features such as memory streaming, webhook function where you can send requests to API without leaking the API, discord webhook notifications, ban the user securely through the application at your discretion. Feel free to join https://discord.gg/keyauth If you are experiencing account issues.

**Customer connection issues?**

This is common amongst all authentication systems. Program obfuscation causes false positives in virus scanners, and with the scale of KeyAuth this is perceived as a malicious domain. So, `keyauth.com` and `keyauth.win` have been blocked by many internet providers. for dashbord, reseller panel, customer panel, use `keyauth.cc`

For API, `keyauth.cc` will not work because I purposefully blocked it on there so `keyauth.cc` doesn't get blocked also. So, you should create your own domain and follow this tutorial video https://www.youtube.com/watch?v=a2SROFJ0eYc. The tutorial video shows you how to create a domain name for 100% free if you don't want to purchase one.

**`KeyAuthApp` instance definition**

Visit and select your application, then click on the **Python** tab

It'll provide you with the code which you should replace with in the `main.py` file.

```PY
keyauthapp = api(
    name = "example", #App name (Manage Applications --> Application name)
    ownerid = "JjPMBVlIOd", #Owner ID (Account-Settings --> OwnerID)
    secret = "db40d586f4b189e04e5c18c3c94b7e72221be3f6551995adc05236948d1762bc", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)
```

**Initialize application**

You don't need to add any code to initalize. KeyAuth will initalize when the instance definition is made.

**Display application information**

```py
print(f"""
App data:
Number of users: {keyauthapp.app_data.numUsers}
Number of online users: {keyauthapp.app_data.onlineUsers}
Number of keys: {keyauthapp.app_data.numKeys}
Application Version: {keyauthapp.app_data.app_ver}
Customer panel link: {keyauthapp.app_data.customer_panel}
""")
```

**Check session validation**

Use this to see if the user is logged in or not.

```py
print(f"Current Session Validation Status: {keyauthapp.check()}")
```

**Check blacklist status**

Check if HWID or IP Address is blacklisted. You can add this if you want, just to make sure nobody can open your program for less than a second if they're blacklisted. Though, if you don't mind a blacklisted user having the program for a few seconds until they try to login and register, and you care about having the quickest program for your users, you shouldn't use this function then. If a blacklisted user tries to login/register, the KeyAuth server will check if they're blacklisted and deny entry if so. So the check blacklist function is just auxiliary function that's optional.

```py
if keyauthapp.checkblacklist():
    print("You've been blacklisted from our application.")
    os._exit(1)
```

**Login with username/password**

```py
user = input('Provide username: ')
password = input('Provide password: ')
keyauthapp.login(user, password)
```

**Register with username/password/key**

```py
user = input('Provide username: ')
password = input('Provide password: ')
license = input('Provide License: ')
keyauthapp.register(user, password, license)
```

**Upgrade user username/key**

Used so the user can add extra time to their account by claiming new key.

> **Warning**
> No password is needed to upgrade account. So, unlike login, register, and license functions - you should **not** log user in after successful upgrade.

```py
user = input('Provide username: ')
license = input('Provide License: ')
keyauthapp.upgrade(user, license)
```

**Login with just license key**

Users can use this function if their license key has never been used before, and if it has been used before. So if you plan to just allow users to use keys, you can remove the login and register functions from your code.

```py
key = input('Enter your license: ')
keyauthapp.license(key)
```

**User Data**

Show information for current logged-in user.

```py
print("\nUser data: ")
print("Username: " + keyauthapp.user_data.username)
print("IP address: " + keyauthapp.user_data.ip)
print("Hardware-Id: " + keyauthapp.user_data.hwid)

subs = keyauthapp.user_data.subscriptions  # Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
    sub = subs[i]["subscription"]  # Subscription from every Sub
    expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
        '%Y-%m-%d %H:%M:%S')  # Expiry date from every Sub
    timeleft = subs[i]["timeleft"]  # Timeleft from every Sub

    print(f"[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")
print("Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print("Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print("Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"Current Session Validation Status: {keyauthapp.check()}")
```

**Show list of online users**

```py
onlineUsers = keyauthapp.fetchOnline()
OU = ""  # KEEP THIS EMPTY FOR NOW, THIS WILL BE USED TO CREATE ONLINE USER STRING.
if onlineUsers is None:
    OU = "No online users"
else:
    for i in range(len(onlineUsers)):
        OU += onlineUsers[i]["credential"] + " "

print("\n" + OU + "\n")
```

**Application variables**

A string that is kept on the server-side of KeyAuth. On the dashboard you can choose for each variable to be authenticated (only logged in users can access), or not authenticated (any user can access before login). These are global and static for all users, unlike User Variables which will be dicussed below this section.

```py
* Get normal variable and print it
data = keyauthapp.var("varName")
print(data)
```

**User Variables**

User variables are strings kept on the server-side of KeyAuth. They are specific to users. They can be set on Dashboard in the Users tab, via SellerAPI, or via your loader using the code below. `discord` is the user variable name you fetch the user variable by. `test#0001` is the variable data you get when fetching the user variable.

```py
* Set up user variable
keyauthapp.setvar("varName", "varValue")
```

And here's how you fetch the user variable:

```py
* Get user variable and print it
data = keyauthapp.getvar("varName")
print(data)
```

**Application Logs**

Can be used to log data. Good for anti-debug alerts and maybe error debugging. If you set Discord webhook in the app settings of the Dashboard, it will send log messages to your Discord webhook rather than store them on site. It's recommended that you set Discord webhook, as logs on site may be deleted after a couple months of their creation.

You can use the log function before login & after login.

```py
* Log message to the server and then to your webhook what is set on app settings
keyauthapp.log("Message")
```

**Ban the user**

Ban the user and blacklist their HWID and IP Address. Good function to call upon if you use anti-debug and have detected an intrusion attempt.

Function only works after login.

```py
keyauthapp.ban()
```

**Server-sided webhooks**

Tutorial video https://www.youtube.com/watch?v=ENRaNPPYJbc

Send HTTP requests to URLs securely without leaking the URL in your application. You should definitely use if you want to send requests to SellerAPI from your application, otherwise if you don't use you'll be leaking your seller key to everyone. And then someone can mess up your application.

1st example is how to send request with no POST data. just a GET request to the URL. `7kR0UedlVI` is the webhook ID, `https://keyauth.win/api/seller/?sellerkey=sellerkeyhere&type=black` is what you should put as the webhook endpoint on the dashboard. This is the part you don't want users to see. And then you have `&ip=1.1.1.1&hwid=abc` in your program code which will be added to the webhook endpoint on the keyauth server and then the request will be sent.

2nd example includes post data. it is form data. it is an example request to the KeyAuth API. `7kR0UedlVI` is the webhook ID, `https://keyauth.win/api/1.2/` is the webhook endpoint.

3rd examples included post data though it's JSON. It's an example reques to Discord webhook `7kR0UedlVI` is the webhook ID, `https://discord.com/api/webhooks/...` is the webhook endpoint.

```py
* example to send normal request with no POST data
data = keyauthapp.webhook("7kR0UedlVI", "&ip=1.1.1.1&hwid=abc")

* example to send form data
data = keyauthapp.webhook("7kR0UedlVI", "", "type=init&name=test&ownerid=j9Gj0FTemM", "application/x-www-form-urlencoded")

* example to send JSON
data = keyauthapp.webhook("7kR0UedlVI", "", "{\"content\": \"webhook message here\",\"embeds\": null}", "application/json")
```

**Download file**

Keep files secure by providing KeyAuth your file download link on the KeyAuth dashboard. Make sure this is a direct download link (as soon as you go to the link, it starts downloading without you clicking anything). The KeyAuth download function provides the bytes, and then you get to decide what to do with those. This example shows how to write it to a file named `text.txt` in the same folder as the program, though you could execute with RunPE or whatever you want.

`385624` is the file ID you get from the dashboard after adding file.

```py
* Download Files form the server to your computer using the download function in the api class
bytes = keyauthapp.file("385624")
f = open("example.exe", "wb")
f.write(bytes)
f.close()
```

**Chat channels**

Allow users to communicate amongst themselves in your program.

Example from the form example on how to fetch the chat messages.

```py
* Get chat messages
messages = keyauthapp.chatGet("CHANNEL")

Messages = ""
for i in range(len(messages)):
Messages += datetime.utcfromtimestamp(int(messages[i]["timestamp"])).strftime('%Y-%m-%d %H:%M:%S') + " - " + messages[i]["author"] + ": " + messages[i]["message"] + "\n"

print("\n\n" + Messages)
```

Example on how to send chat message.

```py
* Send chat message
keyauthapp.chatSend("MESSAGE", "CHANNEL")
```

**How to compile?**

You can either use Pyinstaller or Nuitka.

Links:
- Nutika: https://nuitka.net/
- Pyinstaller: https://pyinstaller.org/

Pyinstaller:
- Basic command: `pyinstaller --onefile main.py`

Nutika:
- Basic command: `python -m nuitka --follow-imports --onefile main.py`
