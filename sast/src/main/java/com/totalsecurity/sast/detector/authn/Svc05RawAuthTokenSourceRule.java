package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.Literal;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.ParameterContext;
import com.totalsecurity.sast.rule.source.ExpressionSourceMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import com.totalsecurity.sast.rule.source.SourceMatch;
import com.totalsecurity.sast.rule.source.SourceRule;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** Source-proven raw authentication token values for SVC-05 only. */
final class Svc05RawAuthTokenSourceRule implements SourceRule {
    static final String ID = "SVC_05_RAW_AUTH_TOKEN_SOURCE";
    private static final String STRING = "java.lang.String";
    private static final Set<String> EXCLUDED_TOKEN_WORDS = Set.of(
            "device", "push", "fcm", "verification", "email", "csrf",
            "pagination", "cursor", "reservation", "business");
    private static final Set<String> NON_VALUE_CONTEXT_WORDS = Set.of(
            "metadata", "meta", "type", "config", "configuration", "name", "key",
            "field", "property", "header", "schema", "format", "algorithm", "alias",
            "path", "id");
    private final Svc05IssuerDiscovery.IssuerTypes issuerTypes;

    Svc05RawAuthTokenSourceRule(Svc05IssuerDiscovery.IssuerTypes issuerTypes) {
        this.issuerTypes = issuerTypes;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<SourceMatch> match(ParameterContext context) {
        if (!isAuthenticationTokenIdentifier(context.parameter().name())
                || context.types().qualifyTypeShape(context.parameter().type())
                        .filter(STRING::equals).isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ParameterSourceMatch(
                ID,
                context.parameter(),
                "raw authentication-token parameter proven by identifier and String type"));
    }

    @Override
    public Optional<SourceMatch> match(CallSiteContext context) {
        if (directStringIssuer(context)
                || issuedTokenRecord(context)
                || authorizationHeader(context)) {
            return Optional.of(new ExpressionSourceMatch(
                    ID,
                    context.call(),
                    "raw authentication-token expression proven by exact source context"));
        }
        return Optional.empty();
    }

    private boolean directStringIssuer(CallSiteContext context) {
        if (!context.receiverBoundToValue() || context.receiverQualifiedType().isEmpty()) {
            return false;
        }
        return issuerTypes.directStringMethods().contains(new Svc05IssuerDiscovery.DirectIssuerMethod(
                context.receiverQualifiedType().orElseThrow(),
                context.methodName(),
                context.argumentCount()));
    }

    private boolean issuedTokenRecord(CallSiteContext context) {
        if (!context.receiverBoundToValue() || context.receiverQualifiedType().isEmpty()) {
            return false;
        }
        return issuerTypes.issuedRecordMethods().contains(
                new Svc05IssuerDiscovery.DirectIssuerMethod(
                        context.receiverQualifiedType().orElseThrow(),
                        context.methodName(),
                        context.argumentCount()));
    }

    private static boolean authorizationHeader(CallSiteContext context) {
        return context.receiverBoundToValue()
                && context.receiverQualifiedType()
                        .filter("jakarta.servlet.http.HttpServletRequest"::equals).isPresent()
                && context.methodName().equals("getHeader")
                && context.argumentCount() == 1
                && isAuthorizationHeaderName(context.arguments().getFirst(), context);
    }

    private static boolean isAuthorizationHeaderName(
            Expression expression, CallSiteContext context) {
        if (expression instanceof Literal literal) {
            return literal.kind().equals("string_literal")
                    && unquote(literal.source()).equalsIgnoreCase("Authorization");
        }
        if (!(expression instanceof FieldAccessExpression field)
                || !field.fieldName().equals("AUTHORIZATION")) {
            return false;
        }
        return typeReference(field.target())
                .flatMap(context.types()::qualifyType)
                .filter("org.springframework.http.HttpHeaders"::equals)
                .isPresent();
    }

    private static Optional<String> typeReference(Expression expression) {
        if (expression instanceof VariableReference reference) {
            return Optional.of(reference.name());
        }
        if (expression instanceof FieldAccessExpression field) {
            return typeReference(field.target()).map(owner -> owner + "." + field.fieldName());
        }
        return Optional.empty();
    }

    private static boolean isAuthenticationTokenIdentifier(String value) {
        Set<String> words = words(value);
        if (words.stream().anyMatch(EXCLUDED_TOKEN_WORDS::contains)
                || words.stream().anyMatch(NON_VALUE_CONTEXT_WORDS::contains)) {
            return false;
        }
        return words.contains("jwt")
                || words.contains("token")
                        && (words.contains("access")
                                || words.contains("refresh")
                                || words.contains("bearer")
                                || words.contains("authorization"));
    }

    private static Set<String> words(String value) {
        List<String> parsed = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!Character.isLetterOrDigit(character)) {
                flush(current, parsed);
                continue;
            }
            if (current.length() > 0 && Character.isUpperCase(character)) {
                char previous = value.charAt(index - 1);
                boolean lowerToUpper = Character.isLowerCase(previous) || Character.isDigit(previous);
                boolean acronymBoundary = Character.isUpperCase(previous)
                        && index + 1 < value.length()
                        && Character.isLowerCase(value.charAt(index + 1));
                if (lowerToUpper || acronymBoundary) {
                    flush(current, parsed);
                }
            }
            current.append(String.valueOf(character).toLowerCase(Locale.ROOT));
        }
        flush(current, parsed);
        return Set.copyOf(new LinkedHashSet<>(parsed));
    }

    private static void flush(StringBuilder current, List<String> words) {
        if (current.length() > 0) {
            words.add(current.toString());
            current.setLength(0);
        }
    }

    private static String unquote(String source) {
        return source.length() >= 2 && source.startsWith("\"") && source.endsWith("\"")
                ? source.substring(1, source.length() - 1)
                : source;
    }
}
