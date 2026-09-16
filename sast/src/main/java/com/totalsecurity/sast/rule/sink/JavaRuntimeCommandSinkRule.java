package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

/** Matches only supported java.lang.Runtime.exec String-command overload shapes. */
public final class JavaRuntimeCommandSinkRule implements SinkRule {
    public static final String ID = "JAVA_RUNTIME_COMMAND_EXECUTION";
    private static final String RECEIVER = "java.lang.Runtime";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (!context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()
                || !context.methodName().equals("exec")
                || context.argumentCount() < 1
                || context.argumentCount() > 3
                || !context.argumentHasType(0, "java.lang.String")) {
            return Optional.empty();
        }
        if (context.argumentCount() >= 2
                && !context.argumentHasType(1, "java.lang.String[]")) {
            return Optional.empty();
        }
        if (context.argumentCount() == 3
                && !context.argumentHasType(2, "java.io.File")) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.COMMAND_EXECUTION,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + ".exec String command argument 0"));
    }
}
