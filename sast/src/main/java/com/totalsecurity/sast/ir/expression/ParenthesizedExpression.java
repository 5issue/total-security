package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record ParenthesizedExpression(Expression expression, SourceLocation location)
        implements Expression {
    public ParenthesizedExpression {
        Objects.requireNonNull(expression, "expression");
        Objects.requireNonNull(location, "location");
    }
}

