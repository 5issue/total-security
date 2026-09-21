package benchmark.ssrf;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

class SsrfVulnerable {
    private RestTemplate restTemplate;

    String fetch(@RequestParam String target) {
        return restTemplate.getForObject(target, String.class);
    }
}
