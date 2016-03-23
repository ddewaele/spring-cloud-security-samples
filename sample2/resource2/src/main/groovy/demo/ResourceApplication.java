package demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@SpringBootApplication
@RestController
@EnableResourceServer
public class ResourceApplication {

	@Autowired
	private HttpServletRequest request;

	@RequestMapping("/")
	public LinkedHashMap<String, String> home() {


		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		System.out.println("____ FOUND USER = " + SecurityContextHolder.getContext().getAuthentication());
		//TODO: Need to find a cleaner way to pass on these credentials
		headers.add("Cookie","JSESSIONID=" + request.getCookies()[0].getValue());
		HttpEntity<String> requestEntity = new HttpEntity<String>("parameters", headers);
		ResponseEntity rssResponse = restTemplate.exchange(
				"http://localhost:8888/resource1",
				HttpMethod.GET,
				requestEntity,
				Map.class);

		rssResponse.getBody();


		LinkedHashMap<String, String> map = new LinkedHashMap<String, String>(2);
		map.put("id", UUID.randomUUID().toString());
		map.put("content", "Hello World from resource 2 with content from resource 1 : [" + rssResponse.getBody() + "]");
		return map;
	}

	public static void main(String[] args) {
		SpringApplication.run(ResourceApplication.class, args);
	}

}
