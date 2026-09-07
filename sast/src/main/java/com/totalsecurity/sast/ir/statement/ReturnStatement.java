package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;
import java.util.Optional;

public record ReturnStatement(Optional<Expression> expression, SourceLocation location)
        implements Statement {
    public ReturnStatement {
        expression = Objects.requireNonNull(expression, "expression");
        Objects.requireNonNull(location, "location");
    }
}

