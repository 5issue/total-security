package benchmark.xss;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;

class XssVulnerable {
    void render(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(input);
    }
}
