package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.rule.context.CallSiteContext;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Conservative propagation for String transformations that do not establish sanitization. */
public final class JavaStringMethodTaintModel implements MethodTaintModel {
    public static final String ID = "JAVA_STRING_VALUE_PROPAGATION";
    private static final String STRING = "java.lang.String";
    private static final Map<String, Set<Integer>> RECEIVER_ONLY = Map.of(
            "trim", Set.of(0),
            "strip", Set.of(0),
            "substring", Set.of(1, 2),
            "toLowerCase", Set.of(0, 1),
            "toUpperCase", Set.of(0, 1));
    private static final Map<String, Set<Integer>> RECEIVER_AND_ARGUMENTS = Map.of(
            "concat", Set.of(1),
            "replace", Set.of(2));

    @Override
    public String id() {
        return ID;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        if (!context.receiverQualifiedType().filter(STRING::equals).isPresent()) {
            return Optional.empty();
        }
        Set<Integer> receiverArities = RECEIVER_ONLY.get(context.methodName());
        if (receiverArities != null && receiverArities.contains(context.argumentCount())) {
            return Optional.of(MethodTaintSemantics.propagateReceiver());
        }
        Set<Integer> combinedArities = RECEIVER_AND_ARGUMENTS.get(context.methodName());
        if (combinedArities != null && combinedArities.contains(context.argumentCount())) {
            return Optional.of(MethodTaintSemantics.propagateReceiverAndArguments());
        }
        return Optional.empty();
    }
}
