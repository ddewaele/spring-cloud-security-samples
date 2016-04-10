## Overview

A simple authserver / gateway / ui / resource pattern.

- Everything goes through the gateway
- Authentication against an auth server
- Both UIs and Resources are behind gateway.
- Everything secured with Oauth2
- Out of the box config (simple annotations)

![](images/sample1.png)

This sample contains the following applications

| Name          | Gateway URL                           | Actual URL                      | Comments                         |
| ------------- | ------------------------------------- | ------------------------------- | -------------------------------- |
| authserver    | http://localhost:9999/uaa             | N/A                             | Auth Server                      |
| gateway       | http://localhost:8888/                | N/A                             | Zuul Proxy gateway               |
| resource      | http://localhost:8888/                | http://localhost:9000/resource/ | simple ui app with an index.html |
| ui            | http://localhost:8888/ui/index.html   | http://localhost:9000/ui/       | simple ui app with an index.html |


- With the user endpoint on the uaa you cannot really do much. You should provide your own user endpoint.

## AuthServer

As basic as can be. Acts as authorization server and resource server (for the user endpoint).


```java
@SpringBootApplication
@RestController
@EnableResourceServer
@EnableAuthorizationServer
public class AuthserverApplication {

	@RequestMapping("/user")
	public Principal user(Principal user) {
		return user;
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

}
```

There is a default user account (defined in application.yml) :

- username = user
- password = password

There is a basic auth popup to authenticate a user (out of the box config)

A ```/user``` endpoint is created that returns the user principal. It looks like this :

```
{
   "details":{
      "remoteAddress":"127.0.0.1",
      "sessionId":null,
      "tokenValue":"9a4de635-3472-4c80-8c52-531ae998681c",
      "tokenType":"bearer",
      "decodedDetails":{
         "remoteAddress":"127.0.0.1",
         "sessionId":null,
         "tokenValue":"9a4de635-3472-4c80-8c52-531ae998681c",
         "tokenType":"Bearer",
         "decodedDetails":null
      }
   },
   "authorities":[
      {
         "authority":"ROLE_USER"
      }
   ],
   "authenticated":true,
   "userAuthentication":{
      "details":{
         "remoteAddress":"0:0:0:0:0:0:0:1",
         "sessionId":"E59AC032B7CA943C167120B26F500197"
      },
      "authorities":[
         {
            "authority":"ROLE_USER"
         }
      ],
      "authenticated":true,
      "principal":{
         "password":null,
         "username":"user",
         "authorities":[
            {
               "authority":"ROLE_USER"
            }
         ],
         "accountNonExpired":true,
         "accountNonLocked":true,
         "credentialsNonExpired":true,
         "enabled":true
      },
      "credentials":null,
      "name":"user"
   },
   "clientOnly":false,
   "oauth2Request":{
      "clientId":"acme",
      "scope":[
         "openid"
      ],
      "requestParameters":{
         "response_type":"code",
         "redirect_uri":"http://localhost:8888/login",
         "state":"32OSe4",
         "code":"z6VuXZ",
         "grant_type":"authorization_code",
         "client_id":"acme"
      },
      "resourceIds":[

      ],
      "authorities":[
         {
            "authority":"ROLE_USER"
         }
      ],
      "approved":true,
      "refresh":false,
      "redirectUri":"http://localhost:8888/login",
      "responseTypes":[
         "code"
      ],
      "extensions":{

      },
      "grantType":"authorization_code",
      "refreshTokenRequest":null
   },
   "principal":{
      "password":null,
      "username":"user",
      "authorities":[
         {
            "authority":"ROLE_USER"
         }
      ],
      "accountNonExpired":true,
      "accountNonLocked":true,
      "credentialsNonExpired":true,
      "enabled":true
   },
   "credentials":"",
   "name":"user"
}
```

## Gateway

Again very simple. We configure it as a Zuul Proxy and we enable SSO via Oauth.

```java
@SpringBootApplication
@EnableZuulProxy
@EnableOAuth2Sso
public class GatewayApplication { 

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

}
```

It's important that all access is going through the gateway. The only component that doesn't go via the gateway is the auth server 
(see sample3 for an example on how to do that)


## UI

A simple spring boot application that exposes some URLs for different roles.

```java
@SpringBootApplication
@EnableResourceServer
public class UiApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(UiApplication.class, args);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/index.html", "/home.html", "/").permitAll()
				.antMatchers("/protected.html").hasRole("USER")
				.antMatchers("/admin.html").hasRole("ADMIN")
				.anyRequest().authenticated()
				.and()
			.csrf()
				.csrfTokenRepository(csrfTokenRepository())
				.and()
			.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);	
	}
```	

