package fixtures;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Statement;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

class SameClassInterproceduralFixture {
    Statement statement;
    RestTemplate restTemplate;
    DirContext directory;

    void sqlEntry(@RequestParam String input) throws Exception {
        sqlHelper(input);
    }

    void sqlHelper(String value) throws Exception {
        String sql = "SELECT * FROM users WHERE id=" + value;
        statement.executeQuery(sql);
    }

    void commandEntry(@PathVariable String input) throws Exception {
        commandHelper(input);
    }

    void commandHelper(String value) throws Exception {
        Runtime.getRuntime().exec(value);
    }

    void pathEntry(@RequestParam String input) throws Exception {
        pathHelper(input);
    }

    void pathHelper(String value) throws Exception {
        Files.readString(Path.of("/data", value));
    }

    void ssrfEntry(@RequestParam String input) {
        ssrfHelper(input);
    }

    void ssrfHelper(String value) {
        restTemplate.getForObject(value, String.class);
    }

    void ldapEntry(@RequestParam String input) throws Exception {
        ldapHelper(input);
    }

    void ldapHelper(String value) throws Exception {
        directory.search("dc=example", value, new SearchControls());
    }

    void twoHopEntry(@RequestParam String input) throws Exception {
        hopA(input);
    }

    void hopA(String value) throws Exception {
        hopB(value);
    }

    void hopB(String value) throws Exception {
        statement.executeQuery(value);
    }

    void returnEntry(@RequestParam String input) throws Exception {
        String sql = buildSql(input);
        statement.executeQuery(sql);
    }

    String buildSql(String value) {
        return "SELECT * FROM users WHERE id=" + value;
    }

    void threeLevelReturnEntry(@RequestParam String input) throws Exception {
        String sql = returnA(input);
        statement.executeQuery(sql);
    }

    String returnA(String value) {
        return returnB(value);
    }

    String returnB(String value) {
        return returnC(value);
    }

    String returnC(String value) {
        return value;
    }

    void trimReturnEntry(@RequestParam String input) throws Exception {
        String sql = trimValue(input);
        statement.executeQuery(sql);
    }

    String trimValue(String value) {
        return value.trim();
    }

    void selectedEntry(@RequestParam String input) throws Exception {
        selectedHelper("clean", input);
    }

    void selectedHelper(String ignored, String used) throws Exception {
        statement.executeQuery(used);
    }

    void thisEntry(@RequestParam String input) throws Exception {
        this.sqlHelper(input);
    }

    void staticStyleEntry(@RequestParam String input) throws Exception {
        SameClassInterproceduralFixture.staticStyleHelper(input, statement);
    }

    static void staticStyleHelper(String value, Statement target) throws Exception {
        target.executeQuery(value);
    }

    void classNameLocalShadow(
            @RequestParam String input, CustomReceiver receiver) throws Exception {
        CustomReceiver SameClassInterproceduralFixture = receiver;
        SameClassInterproceduralFixture.staticStyleHelper(input, statement);
    }

    void classNameParameterShadow(
            CustomReceiver SameClassInterproceduralFixture,
            @RequestParam String input) throws Exception {
        SameClassInterproceduralFixture.staticStyleHelper(input, statement);
    }

    void overloadEntry(@RequestParam String input) throws Exception {
        overloaded(input);
    }

    void overloaded(String value) throws Exception {
        statement.executeQuery(value);
    }

    void overloaded(int value) {}

    void calleeBranchEntry(@RequestParam String input) throws Exception {
        calleeBranch(input, false);
    }

    void calleeBranch(String value, boolean fixed) throws Exception {
        String sql;
        if (fixed) {
            sql = "SELECT 1";
        } else {
            sql = value;
        }
        statement.executeQuery(sql);
    }

    void callerBranchEntry(@RequestParam String input, boolean useInput) throws Exception {
        String value;
        if (useInput) {
            value = input;
        } else {
            value = "clean";
        }
        sqlHelper(value);
    }

    void multipleOrigins(
            @RequestParam String left,
            @RequestHeader String right,
            boolean chooseLeft) throws Exception {
        String value;
        if (chooseLeft) {
            value = left;
        } else {
            value = right;
        }
        sqlHelper(value);
    }

    void cleanArgument() throws Exception {
        sqlHelper("fixed");
    }

    void cleanOverwrite(@RequestParam String input) throws Exception {
        input = "fixed";
        sqlHelper(input);
    }

    void fixedReturnEntry(@RequestParam String input) throws Exception {
        statement.executeQuery(fixedReturn(input));
    }

    String fixedReturn(String ignored) {
        return "SELECT 1";
    }

    void unknownReturnEntry(@RequestParam String input) throws Exception {
        statement.executeQuery(unknownReturn(input));
    }

    String unknownReturn(String value) {
        return externalBuild(value);
    }

    void externalReceiver(@RequestParam String input, CustomReceiver receiver) throws Exception {
        receiver.sqlHelper(input);
    }

    void ambiguousEntry(@RequestParam String input) throws Exception {
        ambiguous(externalBuild(input));
    }

    void ambiguous(String value) throws Exception {
        statement.executeQuery(value);
    }

    void ambiguous(Object value) {}

    void superEntry(@RequestParam String input) throws Exception {
        super.inheritedHelper(input);
    }

    void inheritedHelper(String value) throws Exception {
        statement.executeQuery(value);
    }

    void selfEntry(@RequestParam String input) throws Exception {
        selfRecursive(input);
    }

    void selfRecursive(String value) throws Exception {
        selfRecursive(value);
        statement.executeQuery(value);
    }

    void recursiveReturnEntry(@RequestParam String input) throws Exception {
        statement.executeQuery(recursiveReturn(input));
    }

    String recursiveReturn(String value) {
        return recursiveReturn(value);
    }

    void mutualEntry(@RequestParam String input) throws Exception {
        mutualA(input);
    }

    void mutualA(String value) throws Exception {
        mutualB(value);
    }

    void mutualB(String value) throws Exception {
        mutualA(value);
        statement.executeQuery(value);
    }

    void wrongArityEntry(@RequestParam String input) throws Exception {
        sqlHelper(input, "extra");
    }

    void incompatibleTypeEntry(@RequestParam String input) {
        intHelper(input);
    }

    void intHelper(int value) {}

    void localSql(@RequestParam String input) throws Exception {
        statement.executeQuery(input);
    }

    void xssEntry(@RequestParam String input, HttpServletResponse response) throws Exception {
        xssHelper(input, response);
    }

    void xssHelper(String value, HttpServletResponse response) throws Exception {
        response.setContentType("text/html");
        response.getWriter().write(value);
    }

    void uploadEntry(@RequestParam MultipartFile file, @RequestParam String name)
            throws IOException {
        uploadHelper(file, name);
    }

    void uploadHelper(MultipartFile file, String name) throws IOException {
        file.transferTo(Path.of("/uploads", name));
    }

    void redirectEntry(@RequestParam String input, HttpServletResponse response)
            throws IOException {
        redirectHelper(input, response);
    }

    void redirectHelper(String value, HttpServletResponse response) throws IOException {
        response.sendRedirect(value);
    }

    void xxeEntry(@RequestParam java.io.InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        configureXml(factory);
        factory.newDocumentBuilder().parse(input);
    }

    void configureXml(DocumentBuilderFactory factory) throws Exception {
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
    }

}

class CustomReceiver {
    void sqlHelper(String value) {}
    void staticStyleHelper(String value, Statement target) {}
}
