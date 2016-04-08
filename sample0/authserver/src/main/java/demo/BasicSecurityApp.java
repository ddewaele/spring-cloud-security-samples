package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class BasicSecurityApp extends WebSecurityConfigurerAdapter {

	@RequestMapping("/greet")
	public Greeting greet() {
		return new Greeting();
	}

	class Greeting {
		String msg = "HelloWorld";

		public String getMsg() {
			return msg;
		}
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.formLogin().and().antMatcher("/**").authorizeRequests();

		http
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.and()
				.httpBasic();
	}

	public static void main(String[] args) {
		SpringApplication.run(BasicSecurityApp.class, args);
	}


}
