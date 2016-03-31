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
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
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


		Object responseFromResource1 = null;
		try {

			RestTemplate restTemplate = new RestTemplate();
			HttpHeaders headers = new HttpHeaders();
			System.out.println("____ FOUND USER = " + SecurityContextHolder.getContext().getAuthentication());

			OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
			OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) oAuth2Authentication.getDetails();

			String accessToken = oAuth2AuthenticationDetails.getTokenValue();

			//TODO: Need to find a cleaner way to pass on these credentials
			headers.add("Cookie","JSESSIONID=" + request.getCookies()[0].getValue());
			//headers.add("Authorization", "Bearer: " + accessToken);
			HttpEntity<String> requestEntity = new HttpEntity<String>("parameters", headers);
			ResponseEntity rssResponse = restTemplate.exchange(
					"http://localhost:8888/resource1",
					HttpMethod.GET,
					requestEntity,
					Map.class);

			responseFromResource1 = rssResponse.getBody();

		} catch (Exception ex) {
			responseFromResource1 = ex.getMessage();
		}


		LinkedHashMap<String, String> map = new LinkedHashMap<String, String>(2);
		map.put("id", UUID.randomUUID().toString());
		map.put("content", "Hello World from resource 2 with content from resource 1 : [" + responseFromResource1 + "]");
		return map;
	}

	public static void main(String[] args) {
		SpringApplication.run(ResourceApplication.class, args);
	}

}
