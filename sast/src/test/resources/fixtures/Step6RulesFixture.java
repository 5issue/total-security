package fixtures.step6;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

class Step6RulesFixture {
    private HttpServletRequest request;
    private Statement statement;
    private Connection connection;
    private PreparedStatement preparedStatement;
    private JdbcTemplate jdbcTemplate;
    private EntityManager entityManager;
    private Query query;

    void requestParam(@RequestParam String input) {}

    void pathVariable(@PathVariable String input) {}

    void requestBody(@RequestBody String input) {}

    void requestHeader(@RequestHeader String input) {}

    void cookieValue(@CookieValue String input) {}

    void servletParameter() {
        String value = request.getParameter("name");
        consume(value);
    }

    void jdbcStatement(String sql) {
        statement.executeQuery(sql);
    }

    void jdbcConnection(String sql) {
        connection.prepareStatement(sql);
    }

    void preparedBinding(String input) {
        preparedStatement.setString(1, input);
    }

    void springJdbc(String sql, String input) {
        jdbcTemplate.update(sql, input);
    }

    void jpaNative(String sql) {
        entityManager.createNativeQuery(sql);
    }

    void jpaBinding(String input) {
        query.setParameter(1, input);
    }

    void unmodeled(String input) {
        String value = transform(input);
        consume(value);
    }

    void trimTainted(String input) {
        String value = input.trim();
        consume(value);
    }

    void trimClean() {
        String value = " safe ".trim();
        consume(value);
    }

    void selectedArguments(String left, String right) {
        String value = choose(left, right);
        consume(value);
    }

    void sanitized(String input) {
        String value = verifiedClean(input);
        consume(value);
    }

    void ordinaryStringMethods(String input) {
        String trimmed = input.trim();
        String replaced = input.replace("x", "y");
        consume(trimmed);
        consume(replaced);
    }

    void endToEnd(@RequestParam String input) {
        statement.executeQuery(input);
    }

    void ruleAwareFlow(@RequestParam String input) {
        String value = input.trim();
        statement.executeQuery(value);
    }
}
