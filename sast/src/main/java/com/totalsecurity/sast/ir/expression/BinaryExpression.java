package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record BinaryExpression(
        String operator, Expression left, Expression right, SourceLocation location)
        implements Expression {
    public BinaryExpression {
        Objects.requireNonNull(operator, "operator");
        Objects.requireNonNull(left, "left");
        Objects.requireNonNull(right, "right");
        Objects.requireNonNull(location, "location");
    }
}

