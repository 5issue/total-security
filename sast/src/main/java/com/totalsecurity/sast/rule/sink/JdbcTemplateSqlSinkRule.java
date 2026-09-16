package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

public final class JdbcTemplateSqlSinkRule implements SinkRule {
    public static final String ID = "SPRING_JDBC_TEMPLATE_SQL";
    private static final String RECEIVER = "org.springframework.jdbc.core.JdbcTemplate";
    private static final Set<String> METHODS = Set.of("query", "queryForObject", "update", "execute");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || !METHODS.contains(context.methodName())
                || context.argumentCount() == 0
                || !context.argumentHasType(0, "java.lang.String")) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.SQL_TEXT,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + "." + context.methodName() + " SQL text argument 0"));
    }
}
