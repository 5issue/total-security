package fixtures.recordenum;

import java.sql.Statement;
import org.springframework.web.bind.annotation.RequestBody;

record User(String name, Long id) {}

record AccessToken(String token) {}

record TokenPair(AccessToken accessToken) {}

record LoginRequest(String username) {}

record Value(String value) {
    public String value() {
        return "custom";
    }
}

enum Status {
    ACTIVE,
    SPECIAL {
        @Override
        public boolean enabled() {
            return false;
        }
    };

    public boolean enabled() {
        return true;
    }
}

class PlainType {
    String label() {
        return "plain";
    }
}

interface PlainContract {}

class RecordEnumService {
    private Statement statement;

    void acceptName(String name) {}

    void acceptToken(String token) {}

    void acceptBoolean(boolean value) {}

    void login(String username) {
        statement.executeQuery(username);
    }
}

class RecordEnumController {
    private RecordEnumService service;

    void access(User user) {
        service.acceptName(user.name());
    }

    void chain(TokenPair tokens) {
        service.acceptToken(tokens.accessToken().token());
    }

    void wrongName(User user) {
        user.unknown();
    }

    void wrongArity(User user, String value) {
        user.name(value);
    }

    void invalidTypeReceiver() {
        User.name();
    }

    void unresolvedPattern(Object input) {
        if (input instanceof User User) {
            service.acceptName(User.name());
        }
    }

    void arbitraryClass(PlainType plain) {
        service.acceptName(plain.label());
    }

    void explicit(@RequestBody Value value) {
        service.acceptName(value.value());
    }

    void enumBase() {
        service.acceptBoolean(Status.ACTIVE.enabled());
    }

    void enumDynamic() {
        service.acceptBoolean(Status.SPECIAL.enabled());
    }

    void duplicate(fixtures.recordenum.duplicate.DuplicateRecord value) {
        value.name();
    }

    void login(@RequestBody LoginRequest request) {
        service.login(request.username());
    }
}
