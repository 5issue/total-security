package benchmark.ssrf;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.RestTemplate;

class SsrfSafe {
    private RestTemplate restTemplate;

    String send(@RequestBody String body) {
        return restTemplate.postForObject("https://trusted.example/api", body, String.class);
    }
}
