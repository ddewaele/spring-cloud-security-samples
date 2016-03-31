package demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@SpringBootApplication
@RestController
@EnableResourceServer
@EnableAuthorizationServer
public class AuthserverApplication extends WebSecurityConfigurerAdapter {


	/**
	 *
	 * Instead of returning the principal directly, we're returning a custom user object
	 * that exposes the username and authorities list.
	 *
	 * This way we bypass the issue https://github.com/spring-projects/spring-boot/issues/5482
	 *
	 * @param user
	 * @return
     */
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

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

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

	@Autowired
	protected void registerGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER").and()
				.withUser("admin").password("password").roles("USER", "ADMIN").and()
				.withUser("manager").password("password").roles("MANAGER","USER").and()
				.withUser("planner").password("password").roles("USER", "PLANNER");
	}

}
