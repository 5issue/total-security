package fixtures;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

class XssFixture {
    void requestParam(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(input);
    }

    void pathVariable(@PathVariable String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().print(input);
    }

    void requestBody(@RequestBody String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().println(input);
    }

    void requestHeader(@RequestHeader String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(input);
    }

    void cookieValue(@CookieValue String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(input);
    }

    void servletSource(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(request.getParameter("name"));
    }

    void localAssignment(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String value = input;
        PrintWriter writer = response.getWriter();
        writer.write(value);
    }

    void throughTrim(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String value = input.trim();
        response.getWriter().write(value);
    }

    void fixedPrefix(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write("<div>" + input);
    }

    void fixedSuffix(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(input + "</div>");
    }

    void wrapped(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write("<span>" + input + "</span>");
    }

    void localWriter(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        writer.write(input);
    }

    void compactCharset(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(input);
    }

    void spacedCharset(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("TEXT/HTML; charset=UTF-8");
        response.getWriter().write(input);
    }

    void branchTaint(
            @RequestParam String input,
            boolean selected,
            HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String value;
        if (selected) {
            value = input;
        } else {
            value = "safe";
        }
        response.getWriter().write(value);
    }

    void loopTaint(
            @RequestParam String input,
            boolean active,
            HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String value = "safe";
        while (active) {
            value = input;
            active = false;
        }
        response.getWriter().write(value);
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right,
            HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(left + right);
    }

    void jsonThenHtml(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("application/json");
        response.setContentType("text/html");
        response.getWriter().write(input);
    }

    void repeatedHtml(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.setContentType("text/html");
        response.getWriter().write(input);
    }

    void allBranchesHtml(
            @RequestParam String input,
            boolean selected,
            HttpServletResponse response) throws Exception {
        if (selected) {
            response.setContentType("text/html");
        } else {
            response.setContentType("text/html; charset=UTF-8");
        }
        response.getWriter().write(input);
    }

    void htmlBeforeLoop(
            @RequestParam String input,
            boolean active,
            HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        while (active) {
            response.setContentType("text/html;charset=UTF-8");
            active = false;
        }
        response.getWriter().write(input);
    }

    void fixedLiteral(HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write("<h1>safe</h1>");
    }

    void textPlain(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/plain");
        response.getWriter().write(input);
    }

    void json(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("application/json");
        response.getWriter().write(input);
    }

    void misleadingContentType(
            @RequestParam String input,
            HttpServletResponse response) throws Exception {
        response.setContentType("application/not-text/html");
        response.getWriter().write(input);
    }

    void unset(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.getWriter().write(input);
    }

    void nonLiteralContentType(
            @RequestParam String input,
            String contentType,
            HttpServletResponse response) throws Exception {
        response.setContentType(contentType);
        response.getWriter().write(input);
    }

    void htmlThenJson(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.setContentType("application/json");
        response.getWriter().write(input);
    }

    void mixedContentBranch(
            @RequestParam String input,
            boolean selected,
            HttpServletResponse response) throws Exception {
        if (selected) {
            response.setContentType("text/html");
        } else {
            response.setContentType("application/json");
        }
        response.getWriter().write(input);
    }

    void htmlOrUnset(
            @RequestParam String input,
            boolean selected,
            HttpServletResponse response) throws Exception {
        if (selected) {
            response.setContentType("text/html");
        }
        response.getWriter().write(input);
    }

    void escapedDirect(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(HtmlUtils.htmlEscape(input));
    }

    void escapedLocal(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String escaped = HtmlUtils.htmlEscape(input);
        response.getWriter().write("<div>" + escaped + "</div>");
    }

    void arbitraryEscape(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String escaped = escapeHtml(input);
        response.getWriter().write(escaped);
    }

    void customHtmlUtils(@RequestParam String input, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        String escaped = CustomHtmlUtils.htmlEscape(input);
        response.getWriter().write(escaped);
    }

    void customResponse(
            @RequestParam String input,
            custom.HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        writer.write(input);
    }

    void legacyResponse(
            @RequestParam String input,
            javax.servlet.http.HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        writer.write(input);
    }

    void customWriter(@RequestParam String input, CustomWriter writer) {
        writer.write(input);
    }

    void unrelatedPrintWriter(
            @RequestParam String input,
            PrintWriter writer,
            HttpServletResponse response) {
        response.setContentType("text/html");
        writer.write(input);
    }

    void differentResponse(
            @RequestParam String input,
            HttpServletResponse configured,
            HttpServletResponse output) throws Exception {
        configured.setContentType("text/html");
        output.getWriter().write(input);
    }

    void ordinaryMethod(@RequestParam String input) {
        consume(input);
    }

    void servletOutputStream(
            @RequestBody byte[] input,
            ServletOutputStream output) throws Exception {
        output.write(input);
    }

    @ResponseBody
    String responseBodyReturn(@RequestParam String input) {
        return input;
    }

    String restControllerReturn(@RequestParam String input) {
        return input;
    }

    String thymeleafModel(@RequestParam String input, Model model) {
        model.addAttribute("value", input);
        return "page";
    }

    private String escapeHtml(String input) {
        return input;
    }

    private void consume(String value) {}
}

class CustomWriter {
    void write(String value) {}
}

class CustomHtmlUtils {
    static String htmlEscape(String value) {
        return value;
    }
}
