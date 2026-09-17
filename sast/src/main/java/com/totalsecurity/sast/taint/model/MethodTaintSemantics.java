package com.totalsecurity.sast.taint.model;

import java.util.LinkedHashSet;
import java.util.Set;

public record MethodTaintSemantics(
        MethodTaintBehavior behavior, Set<Integer> selectedArgumentIndexes) {
    public MethodTaintSemantics {
        java.util.Objects.requireNonNull(behavior, "behavior");
        selectedArgumentIndexes = Set.copyOf(new LinkedHashSet<>(selectedArgumentIndexes));
        if (selectedArgumentIndexes.stream().anyMatch(index -> index < 0)) {
            throw new IllegalArgumentException("Selected argument indexes must be non-negative");
        }
        if (behavior != MethodTaintBehavior.PROPAGATE_SELECTED_ARGUMENTS_TO_RETURN
                && !selectedArgumentIndexes.isEmpty()) {
            throw new IllegalArgumentException("Only selected-argument semantics accept indexes");
        }
    }

    public static MethodTaintSemantics unknownReturn() {
        return new MethodTaintSemantics(MethodTaintBehavior.UNKNOWN_RETURN, Set.of());
    }

    public static MethodTaintSemantics propagateReceiver() {
        return new MethodTaintSemantics(
                MethodTaintBehavior.PROPAGATE_RECEIVER_TO_RETURN, Set.of());
    }

    public static MethodTaintSemantics propagateArguments() {
        return new MethodTaintSemantics(
                MethodTaintBehavior.PROPAGATE_ARGUMENTS_TO_RETURN, Set.of());
    }

    public static MethodTaintSemantics propagateSelectedArguments(Set<Integer> indexes) {
        return new MethodTaintSemantics(
                MethodTaintBehavior.PROPAGATE_SELECTED_ARGUMENTS_TO_RETURN, indexes);
    }

    public static MethodTaintSemantics propagateReceiverAndArguments() {
        return new MethodTaintSemantics(
                MethodTaintBehavior.PROPAGATE_RECEIVER_AND_ARGUMENTS_TO_RETURN, Set.of());
    }

    public static MethodTaintSemantics sanitizedReturn() {
        return new MethodTaintSemantics(MethodTaintBehavior.SANITIZED_RETURN, Set.of());
    }

    /** A dependency-proven clean value; unlike SANITIZED_RETURN this is not a security sanitizer. */
    public static MethodTaintSemantics cleanReturn() {
        return new MethodTaintSemantics(MethodTaintBehavior.CLEAN_RETURN, Set.of());
    }
}
