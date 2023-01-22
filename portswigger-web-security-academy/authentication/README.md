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

Vulnerable URL: https://domain/login

This lab is the same as the previous but the difference in the responses are very subtle. An invalid username shows the error message `Invalid username or password.` and a valid username shows the error message `Invalid username or password `
- These differences can be more easily to find using Grep - Extract under Burp Intruder options and highlighting the text to show in one of the columns of the attack results

To solve the lab, log in as `att:buster`

### [Lab: Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing)

Vulnerable URL: https://domain/login

This lab implements an IP-based brute-force protection that can be bypassed with the `X-Forwarded-For` HTTP header. This header identifies the originating IP address of a client connected through a proxy or load balancer. Also, no difference in the responses is shown

To enumerate the user we need to use a Pitchfork-type attack using numbers as the first payload for the header and the simple list payload for the username. The password provided must be very big. A valid username will have a much higher response time than an invalid user (the application checks if the user exists first and then checks if the password is valid)

To brute-force the password we use the same logic as before but change the header to prevent blocks. The request with a 302 response will have the correct password for the user

To solve the lab, log in as `ao:michael`

### [Lab: Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block)

Vulnerable URL: https://domain/login

This lab implements IP blocking after 3 wrong login attempts. To bypass this block we log in with a known username:password to reset the attempts count. To carry this attack, we try 2 combinations of username:password and log in as the known user after

A Pitchfork-type attack can be used with a simple list of usernames (user to break, user to break, known user...) and a simple list of passwords (password to break, password to break, known password...). A script can also be written to brute force this application

To solve the lab log in as `carlos:zxcvbn`


### [Lab: Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)

Vulnerable URL: https://domain/login

This lab implements account lock to stop brute-force attacks. This feature helps us enumerating users. When an invalid user is prompted the account block message never shows up, but when a valid username is provided the message will appear after 3 tries. To enumerate the user we test all users from the list with a random password 4 times, if the last request shows an account block message that is our user. A Cluster Bomb attack can be used to do this enumeration, using a simple list as the username payload and anything as a password 4 times

To get the password we try every password for the user enumerated user. On almost every request the account block or invalid password messages will appear, but on the correct password, no message will appear (even if the account is blocked). A Sniper Attack can be used to get the password, grepping the message to make it easier

To solve the lab, log in as `auction:mobilemail`


## Multifactor authentication


## Other authentication mechanisms
