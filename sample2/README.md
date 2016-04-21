Here we're going to be extending our example a bit by

- AuthServer : Adding some additional users
- AuthServer : Controlling the login process (uses both default and both custom forms)
- AuthServer / Gateway : Controlling the logout process
- AuthServer / Gateway : Introducing POST requests (CSRF)
- ResourceServer : server to server communication


## AuthServer

### Additional users

A quick way to add some users is by wiring the following bean :

```java
    @Autowired
	protected void registerGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER").and()
				.withUser("admin").password("password").roles("USER", "ADMIN").and()
				.withUser("manager").password("password").roles("MANAGER","USER").and()
				.withUser("planner").password("password").roles("USER", "PLANNER");
	}
```

### Controlling the login process 

The default ```@EnableAuthServer``` configuration gives us an HTTP Basic authentication prompt for authenticating users. If we want to customize that we need to configure a WebSecurityConfigurerAdapter.

This is done in the [authserver-formlogin](authserver-formlogin) project with the following code :

```java
@Configuration
	@Order(-20)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
					.formLogin()
						.and()
					.requestMatchers()
						.antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
						.and()
					.authorizeRequests()
						.anyRequest()
						.authenticated();
		}

	}
```	

Now as soon as you start extending the WebSecurityConfigurerAdapter you need to configure the HttpSecurity properly. If you don't configure the httpSecurity you will get an access denied on the oauth urls

```
http://localhost:9999/uaa/oauth/authorize?client_id=acme&redirect_uri=http://localhost:8888/login&response_type=code&state=dgrM6p
```

This is because this URL is meant to be called by an authenticated user, but our httpSecurity isn't been setup to authenticate requests.

We can do that in 2 ways :

- basic authentication (http.httpBasic)
- form based login (http.formLogin)

Here we opted for form baed login.

It's important to specify the correct order, otherwise the resourceserver will take over and you'll get an authorization error.

## The gateway

## The Resource server

Because of the ```@EnableResourceServer``` annotation all requests are secured.

So a call to ```curl -v -X GET http://localhost:9000/greeting``` will result in 

```
< HTTP/1.1 401 Unauthorized
< Server: Apache-Coyote/1.1
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Cache-Control: no-store
< Pragma: no-cache
< WWW-Authenticate: Bearer realm="null", error="unauthorized", error_description="Full authentication is required to access this resource"
< Content-Type: application/json;charset=UTF-8
< Transfer-Encoding: chunked
< Date: Sun, 10 Apr 2016 18:49:13 GMT
< 
* Connection #0 to host localhost left intact
{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}
```

This is telling us we need a bearer token.

Now typically we won't be accessing the resource server directly, but we'll pass through the gateway :

```
curl -v -X GET http://localhost:8888/resource1/greeting
```

The gateway responds with

```
< HTTP/1.1 302 Found
< Server: Apache-Coyote/1.1
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 1; mode=block
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Set-Cookie: JSESSIONID=3346B1E346FADA286CAF8C96101D39C9; Path=/; HttpOnly
< Location: http://localhost:8888/login
< Content-Length: 0
< Date: Sun, 10 Apr 2016 18:50:07 GMT
< 
```

The gateway will only allow authenticated users with a valid session. 

```bash
curl -v -X GET -H "Cookie:JSESSIONID=EA065B7FDEB49E08FF7C002A3E7659F4"  http://localhost:8888/resource1/greeting
```

It will in turn call the underlying resource with the correct Bearer token.

curl -v -X GET -H "Authorization: Bearer 74d0fabd-4106-4fe3-bf5a-26355a412a96"  http://localhost:9000/greeting



### CSRF

When executing a POST to the url from the AngularJS UI, we need to provide a proper CSRF token.

```json
{
   "timestamp":1460315837811,
   "status":403,
   "error":"Forbidden",
   "message":"Invalid CSRF Token 'null' was found on the request parameter '_csrf' or header 'X-CSRF-TOKEN'.",
   "path":"/resource1/greeting"
}
```


#### Request
```
POST /resource1/greeting HTTP/1.1
Host: localhost:8888
Connection: keep-alive
Content-Length: 45
Accept: application/json, text/plain, */*
Origin: http://localhost:8888
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36
Content-Type: application/json;charset=UTF-8
Referer: http://localhost:8888/ui/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8,nl;q=0.6
Cookie: JSESSIONID=EA065B7FDEB49E08FF7C002A3E7659F4
```

#### Response
```
HTTP/1.1 403 Forbidden
Server: Apache-Coyote/1.1
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Sun, 10 Apr 2016 19:17:18 GMT
```


In order to resolve this we need to enable CSRF. We can do this on the gateway level.


```java
	public void configure(HttpSecurity http) throws Exception {
		http
				.antMatcher("/**").authorizeRequests()
				.anyRequest().authenticated()
				.and().csrf().csrfTokenRepository(csrfTokenRepository())
				.and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
				
	}

	private Filter csrfHeaderFilter() {
		return new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request,
											HttpServletResponse response, FilterChain filterChain)
					throws ServletException, IOException {
				CsrfToken csrf = (CsrfToken) request
						.getAttribute(CsrfToken.class.getName());
				if (csrf != null) {
					Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
					String token = csrf.getToken();
					if (cookie == null
							|| token != null && !token.equals(cookie.getValue())) {
						cookie = new Cookie("XSRF-TOKEN", token);
						cookie.setPath("/");
						response.addCookie(cookie);
					}
				}
				filterChain.doFilter(request, response);
			}
		};
	}

	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;
	}	
```	

### Single logout process.

The logout process is a 2-step process in this implementation.
On the gateway level, we provide a convenient way to logout :

```java
.logout()
    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
```

However, this won't log the user out of the authserver, so we need to extend this with the following :

```java
.logout()
    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
    .logoutSuccessUrl("http://localhost:9999/uaa/signout");
```

As you can see, after logging out to the getway, we redirect to a ```signout``` endpoint on the authserver. This signout endpoint is configured like this on the authserver (currently only on the authserver-formlogin)

```java
.logout()
    .logoutRequestMatcher(new AntPathRequestMatcher("/signout"))
    .logoutSuccessUrl("/login")
```




## Server to server communication

When ```resource2``` is trying to communicate with ```resource1```, it can do it in one of the following ways :


## Bad way nr 1

Trying to get the token using the ```SecurityContextHolder```

```
OAuth2Authentication auth =  (OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication();
OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) auth.getDetails();
String token = details.getTokenValue();
```

Although this will work you need to understand the following :

- Casting is never good, and there's a lot of casting here
- Although this will get you a token, you need to understand that gateway protected resources won't access tokens. (only if you call them directly)


## Bad way nr 2

Attempting to retrieve the JSESSIONID and using that to access the protected resource via the Gateway.
This works, but it involves extracting the JSESSIONID fromt he cookie

```java
@Autowired
HttpServletRequest request;


HttpClient httpClient = HttpClients.custom().build();
RestTemplate restTemplate = new RestTemplate();
HttpHeaders headers = new HttpHeaders();
headers.add("Cookie","JSESSIONID " + extractJessionIdFromCookie());

HttpEntity<String> requestEntity = new HttpEntity<String>("parameters", headers);
ResponseEntity rssResponse = restTemplate.exchange(
        constants.getMasterDataProperty("url"),
        HttpMethod.GET,
        requestEntity,
        Map.class);

Map tempMasterData = (Map)rssResponse.getBody();


private String extractJessionIdFromCookie() {
    for(Cookie cookie : request.getCookies()) {
        if ("JSESSIONID".equals(cookie.getName())) {
            return cookie.getValue();
        }
    }
    return null;
}

```

## Semi-Good way

Using ```userInfoRestTemplate``` gives you easy access to the token.

```java
@Autowired
private OAuth2RestTemplate userInfoRestTemplate;


HttpClient httpClient = HttpClients.custom().build();
RestTemplate restTemplate = new RestTemplate();
HttpHeaders headers = new HttpHeaders();
headers.add("Authorization","Bearer " + userInfoRestTemplate.getAccessToken());

HttpEntity<String> requestEntity = new HttpEntity<String>("parameters", headers);
ResponseEntity rssResponse = restTemplate.exchange(
        RESOURCE_URL,
        HttpMethod.GET,
        requestEntity,
        Map.class);

Map tempMasterData = (Map)rssResponse.getBody();
```

But keep in mind, in order for this to work you need :

- A valid user
- An unsecured route on the gateway (as here the authorization will be done on the resource level (token) and not the gateway (JSESSIONID)).
- This won't work with pure server-server communication where no user is involved.


## Good way

Using client credentials. 

If you want to do more server-server communication, you're not really acting on behalf of a user, but you're acting on behalf of the server itself.
For that client credentials are used.

You can get an access token real easy like this :

```
curl acme:acmesecret@localhost:9999/oauth/token -d grant_type=client_credentials
```

It will return this :

```
{"access_token":"d7049fb3-738b-4e5d-8b66-1de4bf2add90","token_type":"bearer","expires_in":43199,"scope":"openid"}
```

You can then use it to access your resources.

```
curl -v -H "Authorization:Bearer d7049fb3-738b-4e5d-8b66-1de4bf2add90" http://localhost:8083/api/full_master_data
```

The client credentials are also useful for testing purposes as you don't need to go through the web flows.



