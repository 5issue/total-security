package com.totalsecurity.sast.rule.sink;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Optional;
import java.util.Set;

/** Matches exact Jakarta Servlet redirect destinations at argument zero. */
public final class JakartaServletRedirectSinkRule implements SinkRule {
    public static final String ID = "JAKARTA_SERVLET_RESPONSE_REDIRECT_TARGET";
    private static final String RECEIVER = "jakarta.servlet.http.HttpServletResponse";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SinkMatch> match(CallSiteContext context) {
        if (context.receiverQualifiedType().filter(RECEIVER::equals).isEmpty()
                || !context.methodName().equals("sendRedirect")
                || !supportedSignature(context)) {
            return Optional.empty();
        }
        return Optional.of(new SinkMatch(
                ID,
                SinkCategory.REDIRECT_TARGET,
                context.call(),
                Set.of(0),
                context.location(),
                RECEIVER + ".sendRedirect redirect target argument 0"));
    }

    private static boolean supportedSignature(CallSiteContext context) {
        if (!context.argumentHasType(0, "java.lang.String")) {
            return false;
        }
        return switch (context.argumentCount()) {
            case 1 -> true;
            case 2 -> context.argumentHasType(1, "boolean")
                    || context.argumentHasType(1, "int");
            case 3 -> context.argumentHasType(1, "int")
                    && context.argumentHasType(2, "boolean");
            default -> false;
        };
    }
}
