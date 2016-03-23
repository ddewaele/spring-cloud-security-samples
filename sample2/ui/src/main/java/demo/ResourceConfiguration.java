package demo;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer
public class ResourceConfiguration
        extends ResourceServerConfigurerAdapter
{

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests()
                    .antMatchers("/login").permitAll()
                    .antMatchers("/protected.html").hasRole("USER")
                    .antMatchers("/admin.html").hasRole("ADMIN");
//                    .and()
//                .authorizeRequests()
//                    .anyRequest()
//                    .authenticated()
//                    .and();

        // @formatter:on
    }
}