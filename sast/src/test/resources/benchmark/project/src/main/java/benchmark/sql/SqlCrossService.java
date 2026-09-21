package benchmark.sql;

import java.sql.Statement;

class SqlCrossService {
    private Statement statement;

    void run(String input) throws Exception {
        statement.executeQuery("SELECT * FROM audit WHERE value='" + input + "'");
    }
}
