# Access control

## Labs

### [Lab: Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

This lab has an unprotected admin panel that can be accessed without login

The path to that panel is in the `robots.txt`

To solve the lab, access https://domain/administrator-panel and delete the user carlos

### [Lab: Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

This lab has an unprotected admin panel that can be accessed without login

The path to that panel can be found in the source code of the index page, 

To solve the lab, access https://domain/admin-pnh6m2 and delete the user carlos

### [Lab: User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

This lab has weak access control to the admin panel

The access control is made with a `admin` cookie that can be set to `true` or `false`

To solve the lab, log in with a normal account, and change the cookie value to `true` on https://domain/my-account, https://domain/admin, and https://domain/admin/delete?username=carlos to delete the user carlos

### [Lab: User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile)

Vulnerable URL: https://domain/my-account/change-email

This URL is used to update the user's email, but if the request data is modified and the property `roleid` is added, the role of the user will be updated in the database

To solve the lab, add `"roleid":2` (the administrator user has a role of 2) in the change email request to leverage the permissions for the user and delete the user carlos

### [Lab: URL-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented)

This lab protects the admin panel and the admin's functionalities of being accessed denying POST requests to those endpoints

This protection can be bypassed with the `X-Original-URL` header. To bypass the protection we need to capture a request to another endpoint of the application and add this header to the request pointing to the required endpoint

To delete a user, the endpoint is https://domain/admin/delete?username=username. If we do a GET request to https://domain/admin/?username=carlos and add the header `X-Original-URL: /admin/delete?username=carlos` we successfully delete the user carlos and solve the lab, bypassing the protection

### [Lab: Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)

This lab implements protection to admin functionalities based on the user logged in, but it can be bypassed

When an administrator changes the permission levels of a user he sends a POST request to https://domain/admin-roles with the `username` and `action` (upgrade or downgrade) as the request data. The POST request is secure, no normal user can make a successful POST request to this endpoint

To bypass this protection, we can make a GET request to this endpoint with the https://domain/admin-roles?username=wiener&action=upgrade URL and leverage the permissions to the user wiener and solve the lab
