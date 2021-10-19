from keyauth import KeyAuthAPI

keyauthapp = KeyAuthAPI("Your Application Name", "Your Owner ID", "Your Application Secret", "Your Application Version", True) # exit_on_failure

print("""
1.Login
2.Register
3.Upgrade
4.License Key Only
""")

ans = input("Select Option: ") 

if ans == "1": 
    user = input('\nProvide username: ')
    password = input('\nProvide password: ')
    keyauthapp.login(user, password)

elif ans == "2":
    user = input('\nProvide username: ')
    password = input('\nProvide password: ')
    license = input('\nProvide License: ')
    keyauthapp.register(user, password, license) 

elif ans == "3":
    user = input('\nProvide username: ')
    license = input('\nProvide License: ')
    keyauthapp.upgrade(user, license)

elif ans == "4":
    key = input('\nEnter your license: ')
    keyauthapp.license(key)

elif ans != "":
  print("\n Not Valid Option") 