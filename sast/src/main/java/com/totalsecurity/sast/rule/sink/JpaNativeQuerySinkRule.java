package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

public final class JpaNativeQuerySinkRule implements SinkRule {
    public static final String ID = "JPA_NATIVE_QUERY_SQL";
    private static final String RECEIVER = "jakarta.persistence.EntityManager";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || !context.methodName().equals("createNativeQuery")
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
                RECEIVER + ".createNativeQuery SQL text argument 0"));
    }
}
