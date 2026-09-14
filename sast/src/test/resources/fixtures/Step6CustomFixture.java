package fixtures.step6custom;

import custom.HttpServletRequest;
import custom.RequestParam;
import custom.Statement;

class Step6CustomFixture {
    private HttpServletRequest request;
    private Statement statement;

    void customAnnotation(@RequestParam String input) {}

    void customCalls(String sql) {
        String value = request.getParameter("name");
        statement.executeQuery(sql);
        consume(value);
    }
}
