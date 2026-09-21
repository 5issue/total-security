package fixtures.lombokgetter;

import java.sql.Statement;
import java.util.List;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.springframework.web.bind.annotation.RequestBody;

@Getter
class User {
    private String name;
    private boolean active;
    private boolean isReady;
    private Boolean enabled;
    private final int count = 1;
    private String[] tags;
    private List<String> aliases;
}

class FieldUser {
    @Getter
    private Long id;
}

@lombok.Getter
class FullyQualifiedUser {
    private String value;
}

@Getter
class Order {
    private OrderStatus status;
}

enum OrderStatus {
    OPEN
}

@Getter
class ExplicitUser {
    private String name;

    String getName() {
        return "safe";
    }
}

class PlainUser {
    private String name;
}

class OrdinaryBean {
    private String value;

    String getValue() {
        return value;
    }
}

@Getter(AccessLevel.NONE)
class DisabledClass {
    private String value;
}

@Getter
class DisabledField {
    @Getter(AccessLevel.NONE)
    private String hidden;
}

@Getter
class StaticUser {
    private static String token;
}

@Getter
@Accessors(fluent = true)
class FluentUser {
    private String name;
}

@Getter
class PrefixedFieldUser {
    @Accessors(prefix = "_")
    private String _name;
}

@Getter
@example.Accessors(fluent = true)
class WrongAccessorsUser {
    private String value;
}

class CaseBase {
    String getName() {
        return "base";
    }
}

@Getter
class CaseSuppressedUser extends CaseBase {
    private String name;

    String getNAME() {
        return "custom";
    }
}

record UserHolder(User user) {}

class LombokService {
    private Statement statement;

    void acceptString(String value) {}

    void acceptLong(Long value) {}

    void acceptBoolean(boolean value) {}

    void acceptWrapper(Boolean value) {}

    void acceptStatus(OrderStatus value) {}

    void query(String sql) throws Exception {
        statement.executeQuery(sql);
    }
}

class LombokController {
    private LombokService service;
    private User stored;

    void classLevel(User user) {
        service.acceptString(user.getName());
    }

    void fieldLevel(FieldUser user) {
        service.acceptLong(user.getId());
    }

    void primitiveBoolean(User user) {
        service.acceptBoolean(user.isActive());
        service.acceptBoolean(user.isReady());
    }

    void wrapperBoolean(User user) {
        service.acceptWrapper(user.getEnabled());
        service.acceptWrapper(user.isEnabled());
    }

    void noAnnotation(PlainUser user) {
        service.acceptString(user.getName());
    }

    void explicit(ExplicitUser user) {
        service.acceptString(user.getName());
    }

    void typeReceiver() {
        service.acceptString(User.getName());
    }

    void unresolvedPattern(Object input) {
        if (input instanceof User User) {
            service.acceptString(User.getName());
        }
    }

    void chained(Order order) {
        service.acceptStatus(order.getStatus());
        order.getStatus().name();
    }

    void duplicate(fixtures.lombokgetter.duplicate.DuplicateOwner value) {
        service.acceptString(value.getName());
    }

    void disabledClass(DisabledClass value) {
        service.acceptString(value.getValue());
    }

    void disabledField(DisabledField value) {
        service.acceptString(value.getHidden());
    }

    void staticField(StaticUser value) {
        service.acceptString(value.getToken());
    }

    void fluentAccessors(FluentUser value) {
        service.acceptString(value.getName());
    }

    void prefixedAccessors(PrefixedFieldUser value) {
        service.acceptString(value.get_name());
    }

    void wrongAccessorsPackage(WrongAccessorsUser value) {
        service.acceptString(value.getValue());
    }

    void caseInsensitiveSuppression(CaseSuppressedUser value) {
        service.acceptString(value.getName());
    }

    void ordinary(OrdinaryBean value) {
        service.acceptString(value.getValue());
    }

    void local(User user) {
        User local = user;
        service.acceptString(local.getName());
    }

    void field() {
        service.acceptString(stored.getName());
    }

    void mixedChain(UserHolder holder) {
        service.acceptString(holder.user().getName());
    }

    void backendCategoryShape(FieldUser category) {
        service.acceptLong(category.getId());
    }

    void fullyQualifiedAnnotation(FullyQualifiedUser value) {
        service.acceptString(value.getValue());
    }

    void supportedFieldShapes(User user) {
        user.getCount();
        user.getTags();
        user.getAliases();
    }

    void tainted(@RequestBody User user) throws Exception {
        service.query(user.getName());
    }
}
