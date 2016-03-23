Questions.md

The AuthorizationServer


Without WebSecurityConfigurerAdapter

```
curl -v http://localhost:9999/uaa/oauth/authorize

*   Trying ::1...
* Connected to localhost (::1) port 9999 (#0)
> GET /uaa/oauth/authorize HTTP/1.1
> Host: localhost:9999
> User-Agent: curl/7.43.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Server: Apache-Coyote/1.1
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Strict-Transport-Security: max-age=31536000 ; includeSubDomains
< Set-Cookie: JSESSIONID=0551F840D0858EBB14BEC0E0F52F3770; Path=/uaa/; HttpOnly
< WWW-Authenticate: Basic realm="Spring"
< Content-Type: application/json;charset=UTF-8
< Transfer-Encoding: chunked
< Date: Wed, 23 Mar 2016 12:28:30 GMT
< 
* Connection #0 to host localhost left intact
{"timestamp":1458736110084,"status":401,"error":"Unauthorized","message":"Full authentication is required to access this resource","path":"/uaa/oauth/authorize"}
```

With WebSecurityConfigurerAdapter

```
curl -v http://localhost:9999/uaa/oauth/authorize
*   Trying ::1...
* Connected to localhost (::1) port 9999 (#0)
> GET /uaa/oauth/authorize HTTP/1.1
> Host: localhost:9999
> User-Agent: curl/7.43.0
> Accept: */*
> 
< HTTP/1.1 302 Found
< Server: Apache-Coyote/1.1
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Set-Cookie: JSESSIONID=38CC1C35323A38ACA8E10AFF1120B64C; Path=/uaa/; HttpOnly
< Location: http://localhost:9999/uaa/login
< Content-Length: 0
< Date: Wed, 23 Mar 2016 12:28:57 GMT
< 
* Connection #0 to host localhost left intact
MacBook-Pro-3:authserver ddewaele$ 
```


Why the difference ? What magic is going on ?