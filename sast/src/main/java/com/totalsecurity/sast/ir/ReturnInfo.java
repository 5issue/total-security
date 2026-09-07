package com.totalsecurity.sast.ir;

import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;
import java.util.Optional;

public record ReturnInfo(Optional<Expression> expression, SourceLocation location) {
    public ReturnInfo {
        expression = Objects.requireNonNull(expression, "expression");
        Objects.requireNonNull(location, "location");
    }
}

