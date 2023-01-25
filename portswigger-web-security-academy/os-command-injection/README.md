# OS command injection

## Labs

### [Lab: OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple)

Vulnerable URL: https://domain/product/stock

This URL sends a payload used to run a script that can be injected. To test the vulnerability we can echo some text `& echo hello` with the `storeId` parameter

To solve the lab run the whoami command `& whoami` with the `storeId` parameter

### [Lab: Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays)

Vulnerable URL: https://domain/product/feedback/submit

This URL handles feedback submissions and can be injected. The email parameter can be injected with OS commands

To test the vulnerability (and solve the lab) we can cause a delay in the response time with the ping command `& ping -c 10 127.0.0.1 &` on the `email` parameter

### [Lab: Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection)

Vulnerable URL: https://domain/product/feedback/submit

To test the vulnerability we can trigger a time delay with the ping function `& ping -c 10 127.0.0.1 &` on the `email` parameter

We can redirect the output of a command to a file and save it on a static folder `& whoami > /var/www/images/whoami.txt &` on the `email` parameter

To get the content of the file (and solve the lab) we can use file traversal on https://domain/image?filename=whoami.txt

### [Lab: Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band)

TODO -> require Burp Collaborator

### [Lab: Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration)

TODO -> require Burp Collaborator
