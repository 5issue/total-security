package benchmark.sql;

import org.springframework.web.bind.annotation.RequestParam;

class SqlCrossController {
    private SqlCrossService service;

    void search(@RequestParam String input) throws Exception {
        service.run(input);
    }
}
