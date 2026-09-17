package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

/** Exact String output positions on java.io.PrintWriter; response lineage is proven separately. */
public final class JavaPrintWriterResponseBodySinkRule implements SinkRule {
    public static final String ID = "JAVA_PRINT_WRITER_RESPONSE_BODY";
    private static final String RECEIVER = "java.io.PrintWriter";
    private static final Set<String> METHODS = Set.of("write", "print", "println");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (context.receiverQualifiedType().filter(RECEIVER::equals).isEmpty()
                || !METHODS.contains(context.methodName())
                || context.argumentCount() != 1
                || !context.argumentHasType(0, "java.lang.String")) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.HTTP_RESPONSE_BODY,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + "." + context.methodName() + " String response-body argument 0"));
    }
}
