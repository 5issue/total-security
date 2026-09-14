package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

public final class JdbcConnectionSqlSinkRule implements SinkRule {
    public static final String ID = "JDBC_CONNECTION_PREPARE_STATEMENT_SQL";
    private static final String RECEIVER = "java.sql.Connection";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || !context.methodName().equals("prepareStatement")
                || context.argumentCount() == 0
                || !context.argumentHasType(0, "java.lang.String")) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + ".prepareStatement SQL text argument 0"));
    }
}
