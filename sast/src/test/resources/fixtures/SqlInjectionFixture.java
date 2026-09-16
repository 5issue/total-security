package fixtures.step7;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

class SqlInjectionFixture {
    private Statement statement;
    private Connection connection;
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;
    private HttpServletRequest request;
    private custom.Statement customStatement;

    void directJdbc(@RequestParam String input) {
        statement.executeQuery(input);
    }

    void assignmentChain(@RequestParam String input) {
        String sql = "SELECT * FROM users WHERE id=" + input;
        String query = sql;
        statement.executeQuery(query);
    }

    void throughTrim(@RequestParam String input) {
        String sql = input.trim();
        statement.executeQuery(sql);
    }

    void directBinary(@RequestParam String input) {
        statement.executeQuery("SELECT * FROM users WHERE id=" + input);
    }

    void branch(boolean flag, @RequestParam String input) {
        String sql;
        if (flag) {
            sql = "SELECT * FROM users WHERE id=" + input;
        } else {
            sql = "SELECT * FROM users";
        }
        statement.executeQuery(sql);
    }

    void loop(boolean active, @RequestParam String input) {
        String sql = "SELECT * FROM users";
        while (active) {
            sql = sql + input;
        }
        statement.executeQuery(sql);
    }

    void connection(@RequestParam String input) {
        String sql = "SELECT * FROM users WHERE id=" + input;
        connection.prepareStatement(sql);
    }

    void jdbcTemplatePositive(@RequestParam String input) {
        String sql = "UPDATE users SET name='" + input + "'";
        jdbcTemplate.update(sql);
    }

    void jpaPositive(@RequestParam String input) {
        entityManager.createNativeQuery("SELECT * FROM users WHERE id=" + input);
    }

    void servletSource() {
        String input = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id=" + input;
        statement.executeQuery(sql);
    }

    void preparedBindingSafe(@RequestParam String input) {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM users WHERE id = ?");
        ps.setString(1, input);
    }

    void jpaBindingSafe(@RequestParam String input) {
        Query query = entityManager.createNativeQuery(
                "SELECT * FROM users WHERE id = :id");
        query.setParameter("id", input);
    }

    void jdbcTemplateBindingSafe(@RequestParam String input, @RequestParam String id) {
        jdbcTemplate.update(
                "UPDATE users SET name = ? WHERE id = ?",
                input,
                id);
    }

    void overwritten(@RequestParam String input) {
        String sql = input;
        sql = "SELECT * FROM users";
        statement.executeQuery(sql);
    }

    void sinkWithoutSource(String sql) {
        statement.executeQuery(sql);
    }

    void sourceWithoutSink(@RequestParam String input) {
        consume(input);
    }

    void customExecuteQuery(@RequestParam String input) {
        customStatement.executeQuery(input);
    }

    void customRequestParam(@custom.RequestParam String input) {
        statement.executeQuery(input);
    }

    void unknownReturn(@RequestParam String input) {
        String sql = customBuilder(input);
        statement.executeQuery(sql);
    }

    void multipleSources(
            boolean flag,
            @RequestParam String left,
            @RequestHeader String right) {
        String sql;
        if (flag) {
            sql = "SELECT * FROM users WHERE name='" + left + "'";
        } else {
            sql = "SELECT * FROM users WHERE name='" + right + "'";
        }
        statement.executeQuery(sql);
    }
}
