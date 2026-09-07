package com.totalsecurity.sast.ir;

import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record AssignmentInfo(
        Expression left, String operator, Expression right, SourceLocation location) {
    public AssignmentInfo {
        Objects.requireNonNull(left, "left");
        Objects.requireNonNull(operator, "operator");
        Objects.requireNonNull(right, "right");
        Objects.requireNonNull(location, "location");
    }
}

