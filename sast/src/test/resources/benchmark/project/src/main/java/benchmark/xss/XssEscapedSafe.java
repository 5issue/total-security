package benchmark.xss;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

class XssEscapedSafe {
    void render(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(HtmlUtils.htmlEscape(input));
    }
}
