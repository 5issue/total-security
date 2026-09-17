package fixtures.crossclass.context;

import jakarta.servlet.http.HttpServletResponse;
import java.nio.file.Path;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.multipart.MultipartFile;

class ContextService {
    void xss(String value, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(value);
    }

    void redirect(String value, HttpServletResponse response) throws Exception {
        response.sendRedirect(value);
    }

    void upload(MultipartFile file, String name) throws Exception {
        file.transferTo(Path.of("/uploads", name));
    }

    void xxe(java.io.InputStream input, DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        factory.newDocumentBuilder().parse(input);
    }
}
