package benchmark.sql;

import java.sql.Statement;
import org.springframework.web.bind.annotation.RequestParam;

class SqlDirectVulnerable {
    private Statement statement;

    void execute(@RequestParam String input) throws Exception {
        String sql = "SELECT * FROM users WHERE name='" + input + "'";
        statement.executeQuery(sql);
    }
}
