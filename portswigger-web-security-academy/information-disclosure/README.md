# Information-disclosure

## Labs

### [Lab: Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages)

Vulnerable URL: https://domain/product?productId=id

If we change the `productId` to a character we receive a cerbose error containing the version of `Apache Struts 2 2.3.31`

To solve the lab, submit the version found: `2.3.31`

### [Lab: Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page)

After reading the index page source we find the comment `<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->`. We can navigate to https://domain/cgi-bin/phpinfo.php and get information on the server, including a `SECRET_KEY` on the environment variables section

To solve the lab, submit the `SECRET_KEY`: `xjo6lz0ygua5zqyggyopnmsig92gv4pp`

### [Lab: Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files)

The file `robots.txt` accessible in https://domain/robots.txt has a disallowed directory `/backup` accessible on https://domain/backup. The file `ProductTemplate.java.bak` has information on the PostgreSQL database, including ther password to access it

To solve the lab, submit the database password `eko7ktp6yhbvsjg7x78e4go90o2tfuyd`

### [Lab: Authentication bypass via information disclosure](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass)

Vulnerable URL: https://domain/admin

This URL can only be accessed by a local user. If we use the `TRACE` method on this URL, we find a `X-Custom-IP-Authorization` header in the request, used do determinate if the request was made from inside or outside the network

We can append this header with a internal IP, such as `127.0.0.1` to appear as we were inse the local network in the requests

To solve the lab, append `X-Custom-IP-Authorization: 127.0.0.1` to the request headers on https://domain/admin to access the admin page and to https://domain/admin/delete?username=carlos to delete the user carlos

### [Lab: Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

This lab has a .git folder exposed that can be downloaded using the extension [DotGit](https://chrome.google.com/webstore/detail/dotgit/pampamgoihgcedonnphgehgondkhikel) or with the command `wget -r https://domain/.git/`

O the .git folder downloaded, the `git log --oneline` command shows a commit entitled `Remove admin password from config`. We can see the diff file from that commit using the command `git diff [commit_id]`. This will show the admin password on a removed line

To solve the lab, log in as `administrator:esjnia56xun1w9hqvged`, go to the admin panel and delete the user carlos
