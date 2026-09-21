package fixtures.lombokgetter.config.importrelative;

import java.sql.Statement;
import lombok.Getter;
import org.springframework.web.bind.annotation.RequestBody;

@Getter
class ImportRelativeUser {
    private String name;
}

class ImportRelativeController {
    private Statement statement;

    void tainted(@RequestBody ImportRelativeUser user) throws Exception {
        statement.executeQuery(user.getName());
    }
}
