package benchmark.redirect;

import jakarta.servlet.http.HttpServletResponse;

class RedirectSafe {
    void redirect(HttpServletResponse response) throws Exception {
        response.sendRedirect("/home");
    }
}
