# Authentication

## Password-based login

### [Lab: Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses)

Vulnerable URL: https://domain/login

This lab allows brute-forcing a username and password. For username brute force a different response is shown for a valid username. After a valid username is discovered we try each password to log in as that username
- This process can be done with two sniper attacks on Burp Intruder, the first changing the username and keeping the password the same and the other changing the password for a valid username. Both attacks use a simple list as a payload
- For the username enumeration phase: A invalid username has the message `Invalid username` and a valid username has the message `Incorrect password` 
- For the password enumeration phase: When the password is correct the response code will be 302 instead of 200

To complete the lab, log in as `agenda:123456789`

### [Lab: Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses)

### [Lab: Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)


## Multifactor authentication


## Other authentication mechanisms
