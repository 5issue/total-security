package com.totalsecurity.sast.rule.source;

import com.totalsecurity.sast.dataflow.DataFlowResult;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import com.totalsecurity.sast.taint.ExpressionTaintSeed;
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.Objects;

public record ExpressionSourceMatch(
        String ruleId, MethodCallExpression expression, String evidence) implements SourceMatch {
    public ExpressionSourceMatch {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(expression, "expression");
        Objects.requireNonNull(evidence, "evidence");
    }

    @Override
    public SourceLocation location() {
        return expression.location();
    }

    @Override
    public TaintSeed toTaintSeed(DataFlowResult dataFlow) {
        Objects.requireNonNull(dataFlow, "dataFlow");
        return new ExpressionTaintSeed(
                ruleId + "@" + location().file() + ":" + location().startLine() + ":" + location().startColumn(),
                expression);
    }
}
