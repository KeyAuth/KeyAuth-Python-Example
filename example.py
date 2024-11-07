#utf-8

'''
KeyAuth.cc Python Example

Go to https://keyauth.cc/app/ and click the Python tab. Copy that code and replace the existing keyauthapp instance in this file.

If you get an error saying it can't find module KeyAuth, try following this https://github.com/KeyAuth/KeyAuth-Python-Example#how-to-compile

If that doesn't work for you, you can paste the contents of KeyAuth.py ABOVE this comment and then remove the "from keyauth import api" and that should work too.

READ HERE TO LEARN ABOUT KEYAUTH FUNCTIONS https://github.com/KeyAuth/KeyAuth-Python-Example#keyauthapp-instance-definition
'''

from hashlib import md5
from keyauth import api
import datetime, os

def get_checksum():
    """
    getting working main file file name ``stack()[1].filename``
    Calculate and return the MD5 checksum of the file specified in argv.
    """
    try:
        '''
        you can simply put your filename like that :
                with open('main.py, "rb") as file
        '''
        with open(__file__.split('\\')[-1], "rb") as file: # You can Use argv[1:] to avoid including the script name
            md5_hash = md5()
            md5_hash.update(file.read())
            return md5_hash.hexdigest()
    except (IndexError, FileNotFoundError, IOError) as e:
        print(f"Error: {e}")
        return None

keyauthapp = api(
    name = "testing_program",
    ownerid = "jNleIQFMNP",
    version = "1.0",
    hash_to_check = get_checksum() # use to verify file hash usefull to check if somone modify the file it return false
)

keyauthfetch = keyauthapp.fetchStats()

print(f"""
{70*'='}
Keyauth python example package.
Replace api arguments with yours.
select option to test using yours.
{70*'='}


                ---------- App data ----------
Number of users: {keyauthfetch['appinfo']['numUsers']}
Number of online users: {keyauthfetch['appinfo']['numOnlineUsers']}
Number of keys: {keyauthfetch['appinfo']['numKeys']}
Application Version: {keyauthfetch['appinfo']['version']}
Customer panel link: {keyauthfetch['appinfo']['customerPanelLink']}
\n
[1] Login username & password.
[2] Register username & password.
[3] Login using license.
[4] Upgrade user License.
[5] Send log/messages.
[6] Keyauth webhook.
[7] Check blacklist.
[8] Check online users.\n
""")

select = input('Input >>> ');os.system('cls')

if select == '1':
    user = input('Provide username: ')
    password = input('Provide password: ')
    res = keyauthapp.login(user, password)
    print(res)

elif select == '2':
    user = input('Provide username: ')
    password = input('Provide password: ')
    license = input('Provide License: ')
    print(keyauthapp.register(user, password, license))

elif select == '3':
    key = input('Enter your license: ')
    keyauth = keyauthapp.license(key)
    print(keyauth)

elif select == '4':
    user = input('Provide username: ')
    license = input('Provide License: ')
    print(keyauthapp.upgrade(user, license))

elif select == '5':
    data = keyauthapp.log("Hello World !")
    print(data)

elif select == '6':
    '''
    replace ipify with the name var of your webhook added
    replace ?format=json with your params
    '''
    data = keyauthapp.webhook('ipify', '?format=json')
    print(data)

elif select == '7':
    if keyauthapp.check_blacklist():
        print("You've been blacklisted from our application.")
    else:
        print('You are not blacklist')

elif select == '8':
    onlineUsers = keyauthapp.fetchOnline()
    try:
        OU = ""
        if not onlineUsers:
            OU = "No online users"
        else:
            for i in range(len(onlineUsers)):
                OU += onlineUsers[i]["credential"] + " "
    except KeyError:
        print(onlineUsers['message'])

else:
    print('Selected Invalid Option !')