package fixtures.step2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {
    private final SampleService service;

    public SampleController(SampleService service) {
        this.service = service;
    }

    @GetMapping("/users")
    public String getUser(@RequestParam String id) {
        String userId = id;
        String value = "prefix-" + userId;
        String alias = (value);
        userId = normalize(userId);
        SampleRequest request = new SampleRequest(userId);
        service.findUser(userId);
        return value;
    }

    private String normalize(String value) {
        return value.trim();
    }
}

interface SampleService {
    String findUser(String id);
}
