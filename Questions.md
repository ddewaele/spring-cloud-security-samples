#Questions.md


## Mixing @EnableResource with WebSecurityConfigurerAdapter / HttpSecurity

Despite having ```.antMatchers("/index.html", "/home.html", "/").permitAll()``` in the UI, I'm getting redirected to uaa. Is this a filter order thing ?


## Redirects when accessing zuul endpoints

Sometimes when accessing a URL through zuul (on port 8888) it redirects back to a url using the original port (ex: 8080). For example when
accessing http://localhost:8888/ui ---> http://localhost:8080/ui (Full authentication is required to access this resource)


```
curl -v -H "Cookie:JSESSIONID=8AA731B33EA3D41A55016DDF41093C86" http://localhost:8888/ui
*   Trying ::1...
* Connected to localhost (::1) port 8888 (#0)
> GET /ui HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/7.43.0
> Accept: */*
> Cookie:JSESSIONID=8AA731B33EA3D41A55016DDF41093C86
> 
< HTTP/1.1 302 Found
< Server: Apache-Coyote/1.1
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< X-Application-Context: application:8888
< Location: http://localhost:8080/ui/
< Date: Fri, 08 Apr 2016 14:42:28 GMT
< Transfer-Encoding: chunked
< 
* Connection #0 to host localhost left intact
```

It occurs with the following zuul route

```
   ui:
      path: /ui/**
      url: http://localhost:8080/ui
 ```

The 302 redirect to http://localhost:8080/ui/ is a container (Tomcat redirect) and there's only 2 things we can do :

- Don't use http://localhost:8888/ui but add a trailing slash
- Change the zuul rule and add a trailing slash


## The AuthorizationServer

- Why am I still seeing the basic auth popup despite having http.formLogin() in the authServer
- 



There is a difference in behavior when extending WebSecurityConfigurerAdapter and when not.


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


