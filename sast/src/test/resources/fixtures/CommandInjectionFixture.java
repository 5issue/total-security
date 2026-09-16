package fixtures;

import java.io.File;
import java.lang.Runtime;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

class CommandInjectionFixture {
    private Runtime runtime = Runtime.getRuntime();

    void requestParam(@RequestParam String input) {
        runtime.exec(input);
    }

    void localRuntime(@RequestParam String input) {
        Runtime localRuntime = Runtime.getRuntime();
        localRuntime.exec(input);
    }

    void parameterRuntime(@RequestParam String input, Runtime suppliedRuntime) {
        suppliedRuntime.exec(input);
    }

    void pathVariable(@PathVariable String input) {
        runtime.exec(input);
    }

    void requestBody(@RequestBody String input) {
        runtime.exec(input);
    }

    void requestHeader(@RequestHeader String input) {
        runtime.exec(input);
    }

    void cookieValue(@CookieValue String input) {
        runtime.exec(input);
    }

    void servletSource(HttpServletRequest request) {
        String command = request.getParameter("command");
        runtime.exec(command);
    }

    void localAssignment(@RequestParam String input) {
        String command = input;
        runtime.exec(command);
    }

    void binaryCommand(@RequestParam String input) {
        runtime.exec("tool " + input);
    }

    void throughTrim(@RequestParam String input) {
        String command = input.trim();
        runtime.exec(command);
    }

    void branch(@RequestParam String input, boolean selected) {
        String command;
        if (selected) {
            command = input;
        } else {
            command = "fixed-command";
        }
        runtime.exec(command);
    }

    void loop(@RequestParam String input, boolean active) {
        String command = "fixed-command";
        while (active) {
            command = input;
            active = false;
        }
        runtime.exec(command);
    }

    void withEnvironment(@RequestParam String input, String[] envp) {
        runtime.exec(input, envp);
    }

    void withEnvironmentAndDirectory(
            @RequestParam String input, String[] envp, File directory) {
        runtime.exec(input, envp, directory);
    }

    void chained(@RequestParam String input) {
        Runtime.getRuntime().exec(input);
    }

    void fixedCommand() {
        runtime.exec("fixed-command");
    }

    void sourceWithoutSink(@RequestParam String input) {
        consume(input);
    }

    void cleanOverwrite(@RequestParam String input) {
        String command = input;
        command = "fixed-command";
        runtime.exec(command);
    }

    void customRuntime(@RequestParam String input, custom.Runtime customRuntime) {
        customRuntime.exec(input);
    }

    void customExecutor(@RequestParam String input, CustomExecutor executor) {
        executor.exec(input);
    }

    void unknownReturn(@RequestParam String input) {
        String command = buildCommand(input);
        runtime.exec(command);
    }

    void unsupportedStringArray(@RequestParam String input, String[] command) {
        runtime.exec(command);
    }

    void ordinaryMethod(@RequestParam String input) {
        consume(input);
    }

    void processBuilder(@RequestParam String input) {
        ProcessBuilder builder = new ProcessBuilder(input);
        builder.start();
    }

    void multipleSources(
            @RequestParam String left,
            @RequestHeader String right) {
        String command = left + right;
        runtime.exec(command);
    }

    private String buildCommand(String input) {
        return input;
    }

    private void consume(String value) {}
}

class CustomExecutor {
    void exec(String command) {}
}
