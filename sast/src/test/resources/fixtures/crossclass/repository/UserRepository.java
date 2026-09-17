package fixtures.crossclass.repository;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Statement;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import org.springframework.stereotype.Repository;

@Repository
class UserRepository {
    private Statement statement;
    private DirContext directory;

    void sql(String value) throws Exception {
        statement.executeQuery(value);
    }

    void command(String value) throws Exception {
        Runtime.getRuntime().exec(value);
    }

    void path(String value) throws Exception {
        Files.readString(Path.of("/data", value));
    }

    void ldap(String value) throws Exception {
        directory.search("dc=example", value, new SearchControls());
    }

    String decorate(String value) {
        return value.trim();
    }
}
