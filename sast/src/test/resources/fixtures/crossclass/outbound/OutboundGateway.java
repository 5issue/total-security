package fixtures.crossclass.outbound;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
class OutboundGateway {
    private RestTemplate restTemplate;

    void request(String target) {
        restTemplate.getForObject(target, String.class);
    }
}
