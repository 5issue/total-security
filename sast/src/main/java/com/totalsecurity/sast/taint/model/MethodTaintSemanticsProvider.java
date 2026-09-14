package com.totalsecurity.sast.taint.model;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.Optional;

@FunctionalInterface
public interface MethodTaintSemanticsProvider {
    Optional<MethodTaintSemantics> semanticsFor(MethodCallExpression call);

    static MethodTaintSemanticsProvider none() {
        return ignored -> Optional.empty();
    }
}
