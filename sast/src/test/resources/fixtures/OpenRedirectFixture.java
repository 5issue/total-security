package fixtures;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

class OpenRedirectFixture {
    void requestParam(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void pathVariable(@PathVariable String input, HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void requestBody(@RequestBody String input, HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void requestHeader(@RequestHeader String input, HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void cookieValue(@CookieValue String input, HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void servletSource(HttpServletRequest request, HttpServletResponse response) {
        String input = request.getParameter("next");
        response.sendRedirect(input);
    }

    void localAssignment(@RequestParam String input, HttpServletResponse response) {
        String target = input;
        response.sendRedirect(target);
    }

    void throughTrim(@RequestParam String input, HttpServletResponse response) {
        String target = input.trim();
        response.sendRedirect(target);
    }

    void taintedPrefix(@RequestParam String input, HttpServletResponse response) {
        String target = input + "/fixed/" + "suffix";
        response.sendRedirect(target);
    }

    void branch(@RequestParam String input, boolean selected, HttpServletResponse response) {
        String target;
        if (selected) {
            target = input;
        } else {
            target = "/home";
        }
        response.sendRedirect(target);
    }

    void loop(@RequestParam String input, boolean active, HttpServletResponse response) {
        String target = "/home";
        while (active) {
            target = input;
            active = false;
        }
        response.sendRedirect(target);
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right,
            HttpServletResponse response) {
        String target = left + right;
        response.sendRedirect(target);
    }

    void booleanOverload(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, true);
    }

    void statusOverload(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, 307);
    }

    void statusAndBooleanOverload(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, 307, true);
    }

    void typedBooleanOverload(
            @RequestParam String input, boolean clearBuffer, HttpServletResponse response) {
        response.sendRedirect(input, clearBuffer);
    }

    void fixedLiteral(HttpServletResponse response) {
        response.sendRedirect("/home");
    }

    void sourceWithoutSink(@RequestParam String input) {
        consume(input);
    }

    void cleanOverwrite(@RequestParam String input, HttpServletResponse response) {
        String target = input;
        target = "/home";
        response.sendRedirect(target);
    }

    void fixedRelativePrefix(@RequestParam String input, HttpServletResponse response) {
        String target = "/safe/" + input;
        response.sendRedirect(target);
    }

    void nestedFixedPrefix(
            @RequestParam String input,
            @RequestHeader String suffix,
            HttpServletResponse response) {
        String target = "/fixed/" + input + suffix;
        response.sendRedirect(target);
    }

    void fixedAbsolutePrefix(@RequestParam String input, HttpServletResponse response) {
        String target = "https://trusted.example/users/" + input;
        response.sendRedirect(target);
    }

    void emptyPrefix(@RequestParam String input, HttpServletResponse response) {
        String target = "" + input;
        response.sendRedirect(target);
    }

    void customResponse(@RequestParam String input, CustomResponse response) {
        response.sendRedirect(input);
    }

    void customSender(@RequestParam String input, RedirectService service) {
        service.sendRedirect(input);
    }

    void legacyResponse(
            @RequestParam String input,
            javax.servlet.http.HttpServletResponse response) {
        response.sendRedirect(input);
    }

    void wrongSecondArgument(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, "wrong");
    }

    void wrongThreeArgumentOrder(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, true, 307);
    }

    void tooManyArguments(@RequestParam String input, HttpServletResponse response) {
        response.sendRedirect(input, 307, true, false);
    }

    void unknownBuilder(@RequestParam String input, HttpServletResponse response) {
        String target = buildRedirect(input);
        response.sendRedirect(target);
    }

    void ordinaryMethod(@RequestParam String input) {
        consume(input);
    }

    void locationHeaderOnly(@RequestParam String input, HttpServletResponse response) {
        response.setHeader("Location", input);
    }

    String springRedirectReturn(@RequestParam String input) {
        return "redirect:" + input;
    }

    RedirectView redirectViewFlow(@RequestParam String input) {
        return new RedirectView(input);
    }

    private String buildRedirect(String input) {
        return input;
    }

    private void consume(String value) {}
}

class CustomResponse {
    void sendRedirect(String target) {}
}

class RedirectService {
    void sendRedirect(String target) {}
}
