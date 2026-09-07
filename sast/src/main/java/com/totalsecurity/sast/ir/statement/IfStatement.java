package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;
import java.util.Optional;

public record IfStatement(
        Expression condition,
        Statement thenBranch,
        Optional<Statement> elseBranch,
        SourceLocation location) implements Statement {
    public IfStatement {
        Objects.requireNonNull(condition, "condition");
        Objects.requireNonNull(thenBranch, "thenBranch");
        elseBranch = Objects.requireNonNull(elseBranch, "elseBranch");
        Objects.requireNonNull(location, "location");
    }
}

