package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record ExpressionStatement(Expression expression, SourceLocation location) implements Statement {
    public ExpressionStatement {
        Objects.requireNonNull(expression, "expression");
        Objects.requireNonNull(location, "location");
    }
}

