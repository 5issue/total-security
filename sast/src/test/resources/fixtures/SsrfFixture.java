package fixtures;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

class SsrfFixture {
    private RestTemplate restTemplate;
    private WebClient webClient;
    private HttpClient httpClient;

    void requestParam(@RequestParam String input) {
        restTemplate.getForObject(input, String.class);
    }

    void pathVariable(@PathVariable String input) {
        restTemplate.getForEntity(input, String.class);
    }

    void requestBody(@RequestBody String input) {
        restTemplate.postForObject(input, "clean-body", String.class);
    }

    void requestHeader(@RequestHeader String input) {
        restTemplate.exchange(input, HttpMethod.GET, null, String.class);
    }

    void cookieValue(@CookieValue String input) {
        restTemplate.execute(input, HttpMethod.GET, null, null);
    }

    void servletSource(HttpServletRequest request) {
        String input = request.getParameter("url");
        restTemplate.delete(input);
    }

    void localAssignment(@RequestParam String input) {
        String target = input;
        restTemplate.getForObject(target, String.class);
    }

    void concatenatedTarget(@RequestParam String input) {
        String target = "https://example.test/" + input;
        restTemplate.getForObject(target, String.class);
    }

    void trimmedTarget(@RequestParam String input) {
        String target = input.trim();
        restTemplate.getForObject(target, String.class);
    }

    void uriCreate(@RequestParam String input) {
        URI uri = URI.create(input);
        restTemplate.getForObject(uri, String.class);
    }

    void directUriCreate(@RequestParam String input) {
        restTemplate.getForObject(URI.create(input), String.class);
    }

    void normalizedUri(@RequestParam String input) {
        URI uri = URI.create(input).normalize();
        restTemplate.getForObject(uri, String.class);
    }

    void branch(@RequestParam String input, boolean selected) {
        String target;
        if (selected) {
            target = input;
        } else {
            target = "https://example.test/fixed";
        }
        restTemplate.getForObject(target, String.class);
    }

    void loop(@RequestParam String input, boolean active) {
        String target = "https://example.test/fixed";
        while (active) {
            target = input;
            active = false;
        }
        restTemplate.getForObject(target, String.class);
    }

    void postForEntity(@RequestParam String input) {
        restTemplate.postForEntity(input, "clean-body", String.class);
    }

    void put(@RequestParam String input) {
        restTemplate.put(input, "clean-body");
    }

    void headForHeaders(@RequestParam String input) {
        restTemplate.headForHeaders(input);
    }

    void optionsForAllow(@RequestParam String input) {
        restTemplate.optionsForAllow(input);
    }

    void patchForObject(@RequestParam String input) {
        restTemplate.patchForObject(input, "clean-body", String.class);
    }

    void fixedString() {
        restTemplate.getForObject("https://example.test/fixed", String.class);
    }

    void fixedUri() {
        restTemplate.getForObject(URI.create("https://example.test/fixed"), String.class);
    }

    void sourceWithoutSink(@RequestParam String input) {
        consume(input);
    }

    void cleanOverwrite(@RequestParam String input) {
        String target = input;
        target = "https://example.test/fixed";
        restTemplate.getForObject(target, String.class);
    }

    void customRestTemplate(@RequestParam String input, custom.RestTemplate customClient) {
        customClient.getForObject(input, String.class);
    }

    void customHttpClient(@RequestParam String input, CustomHttpClient customClient) {
        customClient.getForObject(input, String.class);
    }

    void customUriFactory(@RequestParam String input) {
        URI uri = CustomURI.create(input);
        restTemplate.getForObject(uri, String.class);
    }

    void unknownBuilder(@RequestParam String input) {
        String target = buildUrl(input);
        restTemplate.getForObject(target, String.class);
    }

    void taintedBodyOnly(@RequestBody String input) {
        restTemplate.postForObject("https://example.test/fixed", input, String.class);
    }

    void taintedTemplateVariableOnly(@RequestParam String input) {
        restTemplate.getForObject(
                "https://example.test/users/{id}", String.class, input);
    }

    void ordinaryMethod(@RequestParam String input) {
        consume(input);
    }

    void webClientFlow(@RequestParam String input) {
        webClient.get().uri(input).retrieve();
    }

    void httpClientFlow(@RequestParam String input) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(input)).build();
        httpClient.send(request, null);
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right) {
        String target = left + right;
        restTemplate.getForObject(target, String.class);
    }

    private String buildUrl(String input) {
        return input;
    }

    private void consume(String value) {}
}

class CustomHttpClient {
    void getForObject(String target, Class<?> responseType) {}
}

class CustomURI {
    static URI create(String target) {
        return URI.create(target);
    }
}
