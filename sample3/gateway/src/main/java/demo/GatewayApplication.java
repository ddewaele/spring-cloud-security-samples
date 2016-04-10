package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

@SpringBootApplication
@EnableZuulProxy
@EnableOAuth2Sso
public class GatewayApplication extends WebSecurityConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Bean
	@Primary
	public OAuth2ClientContextFilter dynamicOauth2ClientContextFilter() {
		return new DynamicOauth2ClientContextFilter();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/uaa/**", "/login").permitAll().anyRequest().authenticated()
				.and()
				.csrf().requireCsrfProtectionMatcher(csrfRequestMatcher()).csrfTokenRepository(csrfTokenRepository())
				.and()
				.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
				.logout().permitAll()
				.logoutSuccessUrl("/");
	}

//	@Override
//	public void configure(HttpSecurity http) throws Exception {
//		http
//				.antMatcher("/**").authorizeRequests()
//				//.antMatchers("/index.html", "/home.html", "/","/assets/**").permitAll()
//				.anyRequest().authenticated()
//				.and().csrf().csrfTokenRepository(csrfTokenRepository())
//				.and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
//				.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("http://localhost:9999/uaa/signout");
//	}

//	public void configure(HttpSecurity http) throws Exception {
//		http
////			.httpBasic()
//			.antMatcher("/**")
////				.and()
//				.authorizeRequests()
//				.antMatchers("/index.html", "/home.html", "/").permitAll()
////				.antMatchers("/protected.html").hasRole("USER")
////				.antMatchers("/admin.html").hasRole("ADMIN")
////				.anyRequest().authenticated()
//				.and()
//				.csrf()
//				.csrfTokenRepository(csrfTokenRepository())
//				.and()
//				.addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
//	}


	private RequestMatcher csrfRequestMatcher() {
		return new RequestMatcher() {
			// Always allow the HTTP GET method
			private final Pattern allowedMethods = Pattern.compile("^(GET|HEAD|OPTIONS|TRACE)$");

			// Disable CSFR protection on the following urls:
			private final AntPathRequestMatcher[] requestMatchers = { new AntPathRequestMatcher("/uaa/**") };

			@Override
			public boolean matches(HttpServletRequest request) {
				if (allowedMethods.matcher(request.getMethod()).matches()) {
					return false;
				}

				for (AntPathRequestMatcher matcher : requestMatchers) {
					if (matcher.matches(request)) {
						return false;
					}
				}
				return true;
			}
		};
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


}
