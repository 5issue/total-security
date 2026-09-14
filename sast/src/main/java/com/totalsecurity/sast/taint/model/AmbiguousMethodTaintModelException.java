package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.List;

/** Raised rather than silently choosing conflicting models at the same highest priority. */
public final class AmbiguousMethodTaintModelException extends IllegalStateException {
    private final MethodCallExpression call;
    private final MethodTaintModelPriority priority;
    private final List<String> modelIds;

    public AmbiguousMethodTaintModelException(
            MethodCallExpression call,
            MethodTaintModelPriority priority,
            List<String> modelIds) {
        super("Conflicting method-taint models at " + call.location() + " with priority "
                + priority + ": " + modelIds);
        this.call = call;
        this.priority = priority;
        this.modelIds = List.copyOf(modelIds);
    }

    public MethodCallExpression call() {
        return call;
    }

    public MethodTaintModelPriority priority() {
        return priority;
    }

    public List<String> modelIds() {
        return modelIds;
    }
}
