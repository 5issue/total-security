package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.rule.context.CallSiteContext;
import com.totalsecurity.sast.taint.model.MethodTaintModel;
import com.totalsecurity.sast.taint.model.MethodTaintModelPriority;
import com.totalsecurity.sast.taint.model.MethodTaintSemantics;
import java.util.Map;
import java.util.Optional;

/** Exact call-occurrence return semantics derived from project-local method summaries. */
final class ProjectMethodTaintModel implements MethodTaintModel {
    private static final String ID = "PROJECT_LOCAL_METHOD_SUMMARY";
    private final Map<MethodCallExpression, SameClassMethodSummary> calls;

    ProjectMethodTaintModel(Map<MethodCallExpression, SameClassMethodSummary> calls) {
        this.calls = Map.copyOf(calls);
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public MethodTaintModelPriority priority() {
        return MethodTaintModelPriority.SAME_CLASS_INTERPROCEDURAL;
    }

    @Override
    public Optional<MethodTaintSemantics> match(CallSiteContext context) {
        SameClassMethodSummary summary = calls.get(context.call());
        if (summary == null) {
            return Optional.empty();
        }
        return Optional.of(switch (summary.returnDependency().kind()) {
            case CLEAN -> MethodTaintSemantics.cleanReturn();
            case PARAMETER_DEPENDENT -> MethodTaintSemantics.propagateSelectedArguments(
                    summary.returnDependency().parameterIndexes());
            case UNKNOWN -> MethodTaintSemantics.unknownReturn();
        });
    }
}
