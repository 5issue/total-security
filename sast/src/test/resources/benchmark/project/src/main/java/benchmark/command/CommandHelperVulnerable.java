package benchmark.command;

import org.springframework.web.bind.annotation.RequestParam;

class CommandHelperVulnerable {
    void entry(@RequestParam String input) throws Exception {
        execute(input);
    }

    private void execute(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
}
