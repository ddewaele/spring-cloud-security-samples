package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * A resource controller used in the sample get retrieve greetings (HTTP GET) and save greetings (HTTP POST).
 *
 * This has the EnableResourceServer annotation so all of its methods will be secured.
 *
 */
@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceApplication {

	@RequestMapping(value = "/greeting",method = RequestMethod.GET)
	public Greeting getGreeting() {
		return new Greeting(UUID.randomUUID().toString(),"Hello World from resource 1");
	}

	@RequestMapping(value="/greeting",method= RequestMethod.POST)
	public Greeting saveGreeting(Greeting greeting) {
		System.out.println("Saving greeting : " + greeting);
		return greeting;
	}

	public static void main(String[] args) {
		SpringApplication.run(ResourceApplication.class, args);
	}

}
