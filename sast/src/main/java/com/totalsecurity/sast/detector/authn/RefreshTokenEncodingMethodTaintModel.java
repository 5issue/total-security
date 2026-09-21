package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.ir.expression.FieldAccessExpression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;
import com.totalsecurity.sast.taint.model.MethodTaintSemantics;
import java.util.Optional;
import java.util.Set;

/** AUTHN-11-only propagation proving that encoding is not a cryptographic hash. */
final class RefreshTokenEncodingMethodTaintModel implements MethodTaintModel {
    static final String ID = "AUTHN_11_ENCODING_PROPAGATION";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public MethodTaintModelPriority priority() {
        return MethodTaintModelPriority.LANGUAGE_SPECIFIC_PROPAGATION;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        if (context.receiverQualifiedType().filter("java.lang.String"::equals).isPresent()
                && context.methodName().equals("getBytes")
                && (context.argumentCount() == 0 || context.argumentCount() == 1)) {
            return Optional.of(MethodTaintSemantics.propagateReceiver());
        }
        if (context.methodName().equals("encodeToString")
                && context.argumentCount() == 1
                && base64EncoderFactory(context)) {
            return Optional.of(MethodTaintSemantics.propagateSelectedArguments(Set.of(0)));
        }
        if (context.methodName().equals("formatHex")
                && context.argumentCount() == 1
                && hexFormatFactory(context)) {
            return Optional.of(MethodTaintSemantics.propagateSelectedArguments(Set.of(0)));
        }
        return Optional.empty();
    }

    private static boolean base64EncoderFactory(CallSiteContext context) {
        if (context.receiver().isEmpty()
                || !(context.receiver().orElseThrow() instanceof MethodCallExpression factory)
                || !factory.call().methodName().equals("getEncoder")
                || !factory.call().arguments().isEmpty()
                || factory.call().receiver().isEmpty()) {
            return false;
        }
        return typeReference(factory.call().receiver().orElseThrow())
                .flatMap(context.types()::qualifyType)
                .filter("java.util.Base64"::equals)
                .isPresent();
    }

    private static boolean hexFormatFactory(CallSiteContext context) {
        if (context.receiver().isEmpty()
                || !(context.receiver().orElseThrow() instanceof MethodCallExpression factory)
                || !factory.call().methodName().equals("of")
                || !factory.call().arguments().isEmpty()
                || factory.call().receiver().isEmpty()) {
            return false;
        }
        return typeReference(factory.call().receiver().orElseThrow())
                .flatMap(context.types()::qualifyType)
                .filter("java.util.HexFormat"::equals)
                .isPresent();
    }

    private static Optional<String> typeReference(com.totalsecurity.sast.ir.expression.Expression expression) {
        if (expression instanceof VariableReference reference) {
            return Optional.of(reference.name());
        }
        if (expression instanceof FieldAccessExpression field) {
            return typeReference(field.target()).map(owner -> owner + "." + field.fieldName());
        }
        return Optional.empty();
    }
}
