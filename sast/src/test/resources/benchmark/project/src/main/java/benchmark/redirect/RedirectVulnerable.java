package benchmark.redirect;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;

class RedirectVulnerable {
    void redirect(@RequestParam String target, HttpServletResponse response) throws Exception {
        response.sendRedirect(target);
    }
}
