# Access control

## Labs

### [Lab: Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

This lab has an unprotected admin panel that can be accessed without login

The path to that panel is in the `robots.txt`

To solve the lab, access https://domain/administrator-panel and delete the user `carlos`

### [Lab: Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

This lab has an unprotected admin panel that can be accessed without login

The path to that panel can be found in the source code of the index page, 

To solve the lab, access https://domain/admin-pnh6m2 and delete the user `carlos`

### [Lab: User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

This lab has weak access control to the admin panel

The access control is made with a `admin` cookie that can be set to `true` or `false`

To solve the lab, log in with a normal account, and change the cookie value to `true` on https://domain/my-account, https://domain/admin, and https://domain/admin/delete?username=carlos to delete the user `carlos`

### [Lab: User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

Vulnerable URL: https://domain/my-account/change-email

This URL is used to update the user's email, but if the request data is modified and the property `roleid` is added, the role of the user will be updated in the database

To solve the lab, add `"roleid":2` (the administrator user has a role of 2) in the change email request to leverage the permissions for the user and delete the user `carlos`

### [Lab: URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

This lab protects the admin panel and the admin's functionalities of being accessed denying POST requests to those endpoints

This protection can be bypassed with the `X-Original-URL` header. To bypass the protection we need to capture a request to another endpoint of the application and add this header to the request pointing to the required endpoint

To delete a user, the endpoint is https://domain/admin/delete?username=username. If we do a GET request to https://domain/admin/?username=carlos and add the header `X-Original-URL: /admin/delete?username=carlos` we successfully delete the user `carlos` and solve the lab, bypassing the protection

### [Lab: Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

This lab implements protection to admin functionalities based on the user logged in, but it can be bypassed

When an administrator changes the permission levels of a user he sends a POST request to https://domain/admin-roles with the `username` and `action` (upgrade or downgrade) as the request data. The POST request is secure, no normal user can make a successful POST request to this endpoint

To bypass this protection, we can make a GET request to this endpoint with the https://domain/admin-roles?username=wiener&action=upgrade URL and leverage the permissions to the user wiener and solve the lab

### [Lab: User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

This lab has a horizontal privilege escalation on my account page. For a user logged in, the link to that page is https://domain/my-account?id=username. If a user logged in changes the value of the parameter `id` to another user they can see information on the other user

To solve the lab, access https://domain/my-account?id=carlos logged in as `wiener`, and submit the API key for the user `carlos`

### [Lab: User ID controlled by request parameter, with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

This lab has a horizontal privilege escalation on my account page. For a user logged in, the link to that page is https://domain/my-account?id=uid. If a user logged in changes the value of the parameter `id` to another user `UID` they can see information on the other user

To find the `UID`, open a post written by the user `carlos`, and click on his name. The page `https://domain/blogs?userId=569d594f-57ae-4030-b0ed-970e189e74b1` will open, containing the `UID`

To solve the lab, access https://domain/my-account?id=569d594f-57ae-4030-b0ed-970e189e74b1 logged in as `wiener`, and submit the API key for the user `carlos`

### [Lab: User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect)

This lab has a horizontal privilege escalation on my account page. For a user logged in, the link to that page is https://domain/my-account?id=username. If a user logged in changes the value of the parameter `id` to another user they get redirected to the login page

If that request is made with Burp Repeater, the response will be received with the user API key before the redirect

To solve the lab, submit the API key for the user`carlos`

### [Lab: User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure)

Vulnerable URL: https://domain/my-account?id=username

The `my account` page has a change password field with the current user password. This URL doesn't implement access control and we can access the `my account` page from other users and see their password

To solve the lab, go to the admin account page `my-account?id=administrator`, get the password, log in to the account and delete the user `carlos`

### [Lab: Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references)

Vulnerable URL: https://domain/download-transcript/[number].txt

This application has a chat functionality that has a download transcript function. To download a transcript, a GET request is made to `/download-transcript/[number].txt`. This URL is vulnerable to IDOR, since we can download transcripts from other user's chats, changing the `[number]`

To solve the lab, download the transcript `1.txt` containing a password and log in with the credentials `carlos:ul5d06ptkoiapson298m`

### [Lab: Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step)

This lab has an upgrade account functionality for the admin user. This functionality is done with 2 steps: POST request to `/admin-roles` with the username and action to execute (upgrade or downgrade) as data, which renders a confirmation screen to the administrator; another POST request to the same endpoint with the action, confirmed and username as data

The first step implements access control. If a user without privileges tries to upgrade an account an Unauthorized error will be shown. The second step is not protected

To solve the lab, send a POST request to https://domain/admin-roles with `action=upgrade&confirmed=true&username=wiener` as the data to upgrade the user `wiener` as the administrator

### [Lab: Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control)

This lab used the `Referer` header to control the access to admin functions. The URL https://domain/admin-roles?username=username&action=action checks if the user trying to upgrade an account is an administrator with the previous page the user visited (with the `Referer` header). If the user came from https://domain/admin the function is executed

The `/admin` page is protected with other mechanisms and prevents accesses even with the correct referrer

To solve the lab, send a GET request to https://domain/admin-roles?username=wiener&action=upgrade to upgrade the account privileges with the header `Referer: https://domain/admin`
