package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.ClassInfo;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.ParameterInfo;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.ir.expression.VariableReference;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.rule.context.CallSiteContextResolver;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Conservative direct-call resolver for methods declared by one Java class. */
public final class SameClassCallResolver {
    private final JavaFileInfo file;
    private final ClassInfo type;
    private final LightweightTypeContext types;

    public SameClassCallResolver(JavaFileInfo file, ClassInfo type) {
        this.file = Objects.requireNonNull(file, "file");
        this.type = Objects.requireNonNull(type, "type");
        this.types = new LightweightTypeContext(file);
    }

    public Optional<SameClassCallResolution> resolve(
            MethodInfo caller, MethodCallExpression call, CallSiteContextResolver contexts) {
        CallSiteContext context = contexts.resolve(call);
        List<MethodInfo> named = type.methods().stream()
                .filter(method -> method.kind() == MethodKind.METHOD)
                .filter(method -> method.name().equals(context.methodName()))
                .toList();
        if (named.isEmpty()) {
            return Optional.empty();
        }
        Optional<UnsupportedInterproceduralReason> receiverProblem = receiverProblem(context);
        if (receiverProblem.isPresent()) {
            return Optional.of(unsupported(caller, call, receiverProblem.orElseThrow(),
                    "Receiver does not prove a direct call on " + type.name()));
        }

        List<MethodInfo> sameArity = named.stream()
                .filter(method -> method.parameters().size() == context.argumentCount())
                .toList();
        if (sameArity.isEmpty()) {
            return Optional.of(unsupported(caller, call,
                    UnsupportedInterproceduralReason.WRONG_ARITY,
                    "No same-class overload has argument count " + context.argumentCount()));
        }
        if (sameArity.size() == 1) {
            MethodInfo candidate = sameArity.getFirst();
            if (hasKnownTypeMismatch(context, candidate)) {
                return Optional.of(unsupported(caller, call,
                        UnsupportedInterproceduralReason.INCOMPATIBLE_ARGUMENT_TYPE,
                        "Known argument type is incompatible with the only same-class candidate"));
            }
            return Optional.of(resolved(caller, call, candidate));
        }

        List<MethodInfo> exact = sameArity.stream()
                .filter(method -> exactTypes(context, method))
                .toList();
        if (exact.size() == 1) {
            return Optional.of(resolved(caller, call, exact.getFirst()));
        }
        boolean unknownType = context.argumentQualifiedTypes().stream().anyMatch(Optional::isEmpty)
                || sameArity.stream().flatMap(method -> method.parameters().stream())
                        .map(ParameterInfo::type)
                        .map(types::qualifyTypeShape)
                        .anyMatch(Optional::isEmpty);
        UnsupportedInterproceduralReason reason = unknownType
                ? UnsupportedInterproceduralReason.UNKNOWN_ARGUMENT_TYPE
                : UnsupportedInterproceduralReason.AMBIGUOUS_OVERLOAD;
        return Optional.of(unsupported(caller, call, reason,
                "Same-class overload cannot be resolved uniquely by exact lightweight types"));
    }

    private Optional<UnsupportedInterproceduralReason> receiverProblem(CallSiteContext context) {
        if (context.receiver().isEmpty()) {
            return Optional.empty();
        }
        Expression receiver = context.receiver().orElseThrow();
        if (!(receiver instanceof VariableReference reference)) {
            return Optional.of(UnsupportedInterproceduralReason.DYNAMIC_RECEIVER);
        }
        if (reference.name().equals("this")) {
            return Optional.empty();
        }
        if (reference.name().equals("super")) {
            return Optional.of(UnsupportedInterproceduralReason.INHERITED_METHOD);
        }
        String currentFqn = file.packageName().map(pkg -> pkg + "." + type.name()).orElse(type.name());
        if (reference.name().equals(type.name()) || reference.name().equals(currentFqn)) {
            if (context.receiverBoundToValue()) {
                return Optional.of(UnsupportedInterproceduralReason.DYNAMIC_RECEIVER);
            }
            return context.receiverQualifiedType().filter(currentFqn::equals).isPresent()
                    ? Optional.empty()
                    : Optional.of(UnsupportedInterproceduralReason.DYNAMIC_RECEIVER);
        }
        return Optional.of(UnsupportedInterproceduralReason.DYNAMIC_RECEIVER);
    }

    private boolean exactTypes(CallSiteContext context, MethodInfo method) {
        List<Optional<String>> arguments = context.argumentQualifiedTypes();
        List<Optional<String>> parameters = method.parameters().stream()
                .map(ParameterInfo::type)
                .map(types::qualifyTypeShape)
                .toList();
        for (int index = 0; index < arguments.size(); index++) {
            if (arguments.get(index).isEmpty()
                    || parameters.get(index).isEmpty()
                    || !arguments.get(index).equals(parameters.get(index))) {
                return false;
            }
        }
        return true;
    }

    private boolean hasKnownTypeMismatch(CallSiteContext context, MethodInfo method) {
        for (int index = 0; index < context.argumentCount(); index++) {
            Optional<String> argument = context.argumentQualifiedTypes().get(index);
            Optional<String> parameter =
                    types.qualifyTypeShape(method.parameters().get(index).type());
            if (argument.isPresent() && parameter.isPresent()
                    && !argument.orElseThrow().equals(parameter.orElseThrow())) {
                return true;
            }
        }
        return false;
    }

    private static SameClassCallResolution resolved(
            MethodInfo caller, MethodCallExpression call, MethodInfo target) {
        return new SameClassCallResolution(
                caller, call, SameClassCallStatus.RESOLVED,
                Optional.of(target), Optional.empty());
    }

    private static SameClassCallResolution unsupported(
            MethodInfo caller,
            MethodCallExpression call,
            UnsupportedInterproceduralReason reason,
            String detail) {
        return new SameClassCallResolution(
                caller, call, SameClassCallStatus.UNSUPPORTED, Optional.empty(),
                Optional.of(new UnsupportedInterproceduralFlow(reason, detail, call.location())));
    }
}
