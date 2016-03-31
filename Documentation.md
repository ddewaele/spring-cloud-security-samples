#High level architecture

## Focus

- Authentication & SSO
- Single sign out
- Authorization (Role and scope based)
- Fine grained access control on backend resources / UIs
- Page based access controls (htmls) * REST controller method based access control
- Backend to backend communication
- CSRF

## Authorization server

### Details

- A SpringBoot application
- Extending WebSecurityConfigurerAdapter
- A RestController (to provide the /user endpoint)
- A Resource Server (?)
- The Authorization server (to provide the oauth2 paths)

```
@SpringBootApplication
@RestController
@EnableResourceServer
@EnableAuthorizationServer
public class AuthserverApplication extends WebSecurityConfigurerAdapter {
```

### User endpoint

- A user endpoint that is used by ResourceServers to validate the token.
- Returns a user object consisting of a ```username``` and ```authorities``` list (roles)
- Endpoint is used throughout the flow to validae the identifiy of the user
- When /user is available, the system knows the user is logged in.

```java
	@RequestMapping("/user")
	public SimpleUser user(Principal user) {
		List<String> authorities = new ArrayList<>();

		//TODO: we should try to avoid casting like this.
		Collection<GrantedAuthority> oauthAuthorities = ((OAuth2Authentication) user).getAuthorities();

		for (GrantedAuthority grantedAuthority : oauthAuthorities) {
			authorities.add(grantedAuthority.getAuthority());
		}

		return new SimpleUser(user.getName(), authorities);
	}

	class SimpleUser {

		String username;
		List<String> authorities;

		SimpleUser(String username, List<String> authorities) {
			this.username=username;
			this.authorities =authorities;
		}

		public String getUsername() {
			return username;
		}

		public List<String> getAuthorities() {
			return authorities;
		}
	}
```

### We need to tune the HttpSecurity rules (as we now implement WebSecurityConfigurerAdapter)

```
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.formLogin().loginPage("/login").permitAll()
				.and()
				.requestMatchers().antMatchers("/uaa/login", "/uaa/oauth/authorize", "/uaa/oauth/confirm_access")
				.and()
				.authorizeRequests().anyRequest().authenticated();
		// @formatter:on
	}
```

Question : Why is it not showing a form based login (but an http basic auth popup instead)


### AuthenticationManager

We're registring a brean that configurues the auth manager with an in-memory store of some users with different roles.

```
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



### Properties

Wen need to define the following properties.

```
server.port: 9999
server.contextPath: /uaa
security.sessions: if-required
security.oauth2.client.clientId: acme
security.oauth2.client.clientSecret: acmesecret
security.oauth2.client.authorized-grant-types: authorization_code,refresh_token,password
security.oauth2.client.scope: openid
```

## Gateway

### Details

- Spring Boot Application
- Zuul Proxy
- Enables Oauth2 SSO

```	
@SpringBootApplication
@EnableZuulProxy
@EnableOAuth2Sso
public class GatewayApplication {
```



### Properties

The gateway will be the entry point for the user, as such it needs to handle the authentication.
As we're using Oauth we'll be using the @EnableOAuth2SSO annotation to ensure that it goes to the auth server.
It needs to know where to find the oauth2 server. so we need to provide the oauth2 client properties 

If we remove the @enableOauth2SSO annotation, it would just revert to basic authentication, with a generated password for the user.


```
security:
  oauth2:
    client:
      accessTokenUri: http://localhost:9999/uaa/oauth/token
      userAuthorizationUri: http://localhost:9999/uaa/oauth/authorize
      clientId: acme
      clientSecret: acmesecret
    resource:
      userInfoUri: http://localhost:9999/uaa/user
```


## Resource servers

Resource servers can be pure backend server, offering pure backend functionality.
But they can also be UI servers, offering up web pages


### UI Resource


We have the following UI REST services :

http://localhost:8888/ui/uiservice/publicService
http://localhost:8888/ui/uiservice/authenticatedService
http://localhost:8888/ui/uiservice/userService
http://localhost:8888/ui/uiservice/managerService
http://localhost:8888/ui/uiservice/adminService

```
@RestController
@RequestMapping("/uiservice")
public class UIService {


    @RequestMapping("/publicService")
    public ServiceResponse publicService() {
        return new ServiceResponse("public");
    }

    @RequestMapping("/authenticatedService")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ServiceResponse authenticatedService() {
        return new ServiceResponse("authenticated");
    }

    @RequestMapping("/userService")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ServiceResponse userService() {
        return new ServiceResponse("user");
    }

    @RequestMapping("/managerService")
    @PreAuthorize("hasRole('ROLE_MANAGER')")
    public ServiceResponse managerService() {
        return new ServiceResponse("manager");
    }

    @RequestMapping("/adminService")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ServiceResponse adminService() {
        return new ServiceResponse("admin");
    }

    class ServiceResponse {
        private String msg;

        ServiceResponse(String msg) {
            this.msg=msg;
        }

        public String getMsg() {
            return msg;
        }
    }

}
```

As you can see we can do authorization based on the ```@PreAuthorize``` annotation providing we have the following configuration :

```
/**
 *
 * http://stackoverflow.com/questions/29797721/oauth2-security-expressions-on-method-level
 * http://stytex.de/blog/2016/02/01/spring-cloud-security-with-oauth2/
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MethodSecurityConfiguration extends GlobalMethodSecurityConfiguration {

  @Override
  protected MethodSecurityExpressionHandler createExpressionHandler() {
    return new OAuth2MethodSecurityExpressionHandler();
  }
}
```

Our UI in any case needs to be a resource server is well, provided by the following class: 

```
@Configuration
@EnableResourceServer
public class ResourceConfiguration extends ResourceServerConfigurerAdapter
{

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/protected.html").hasRole("USER")
                .antMatchers("/admin.html").hasRole("ADMIN");
    }

}
```

The ```ResourceServerConfigurerAdapter``` allows us to authorize resources using the standard spring security matchers.
This gives us the following UI based page resources

http://localhost:8888/ui/#/				   (public url ?)
http://localhost:8888/ui/protected.html    (user role required)
http://localhost:8888/ui/admin.html 	   (admin role required)
	


## Questions

### Questions (AuthServer)

- Why no form based login
- When users login, they need to authenticate and then get an authorization screen. In case of pure Auth2 SSO, is it possible to automatically authorize the user for a certain scope, so that they only see the login (authentication) page, and not the oauth2 authorization page
- Spring uses the scope openid, is this somehow related to OpenID connect ?
- How to do single sign out


Sometimes zuul redirects back to the resource


http://localhost:8888/planning-ui/				redirects to http://localhost:8800/planning/index.html

http://localhost:8888/planning-ui/index.html    status at works fine

Related to 

 @Override
 public void addViewControllers(ViewControllerRegistry registry) {
    registry.addViewController("/").setViewName("redirect:/index.html");
 }

when ommitted, it stays at port 8888 but displays the http://localhost:8800/planning/ content ( = REST API)


