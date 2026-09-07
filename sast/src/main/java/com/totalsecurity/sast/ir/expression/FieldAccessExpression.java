package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record FieldAccessExpression(
        Expression target, String fieldName, SourceLocation location) implements Expression {
    public FieldAccessExpression {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(fieldName, "fieldName");
        Objects.requireNonNull(location, "location");
    }
}

