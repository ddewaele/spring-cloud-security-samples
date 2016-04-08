package demo;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

//@Configuration
//@EnableResourceServer
//@Order(97)
public class ResourceConfiguration extends ResourceServerConfigurerAdapter {
//
//    @Override
//    public void configure(final HttpSecurity http) throws Exception {
////        http
////                .authorizeRequests()
////                    .antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access").permitAll()
////                    .anyRequest().authenticated();
////                    .and()
////                .formLogin();
////        super.configure(http);
//    }

    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .formLogin().loginPage("/login").permitAll()
                .and()
                .requestMatchers()
                .antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access","/images/**")
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                    .formLogin();
        // @formatter:on
    }
}