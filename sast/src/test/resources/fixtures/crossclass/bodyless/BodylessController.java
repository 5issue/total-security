package fixtures.crossclass.bodyless;

import fixtures.crossclass.service.UserService;
import java.sql.Statement;
import org.springframework.web.bind.annotation.RequestParam;

class BodylessController {
    private AbstractService service;
    private UserService userService;
    private Statement statement;

    void bodylessCall(@RequestParam String input) {
        service.query(input);
    }

    void bodylessReturn(@RequestParam String input) throws Exception {
        String result = service.query(input);
        statement.executeQuery(result);
    }

    void normal(@RequestParam String input) throws Exception {
        userService.sql(input);
    }
}
