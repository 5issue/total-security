package benchmark.sql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import org.springframework.web.bind.annotation.RequestParam;

class SqlPreparedSafe {
    private Connection connection;

    void search(@RequestParam String input) throws Exception {
        PreparedStatement statement =
                connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        statement.setString(1, input);
    }
}
