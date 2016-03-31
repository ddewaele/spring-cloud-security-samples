package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceApplication {

	@RequestMapping("/")
	public Map<String, String> home() {
		Map<String, String> map = new LinkedHashMap<String, String>(2);
		map.put("id", UUID.randomUUID().toString());
		map.put("content", "Hello World from resource 1");
		return map;
	}

	public static void main(String[] args) {
		SpringApplication.run(ResourceApplication.class, args);
	}

}
