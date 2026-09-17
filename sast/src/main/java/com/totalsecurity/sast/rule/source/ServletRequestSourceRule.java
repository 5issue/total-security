package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Map;
import java.util.Optional;

public final class ServletRequestSourceRule implements SourceRule {
    public static final String ID = "SERVLET_HTTP_REQUEST_VALUE";
    private static final String RECEIVER = "jakarta.servlet.http.HttpServletRequest";
    private static final Map<String, Integer> METHODS = Map.of(
            "getParameter", 1,
            "getHeader", 1,
            "getQueryString", 0,
            "getInputStream", 0);

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SourceMatch> match(CallSiteContext context) {
        Integer argumentCount = METHODS.get(context.methodName());
        if (argumentCount == null
                || context.argumentCount() != argumentCount
                || !context.receiverQualifiedType().filter(RECEIVER::equals).isPresent()) {
            return Optional.empty();
        }
        return Optional.of(new ExpressionSourceMatch(
                ID,
                context.call(),
                RECEIVER + "." + context.methodName() + " return value"));
    }
}
