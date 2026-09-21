package benchmark.command;

import org.springframework.web.bind.annotation.RequestParam;

class CommandConstantSafe {
    void execute(@RequestParam String unused) throws Exception {
        Runtime.getRuntime().exec("date");
    }
}
