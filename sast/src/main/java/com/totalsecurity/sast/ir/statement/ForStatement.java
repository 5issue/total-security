package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record ForStatement(
        List<Statement> initializers,
        Optional<Expression> condition,
        List<Expression> updates,
        Statement body,
        SourceLocation location) implements Statement {
    public ForStatement {
        initializers = List.copyOf(initializers);
        condition = Objects.requireNonNull(condition, "condition");
        updates = List.copyOf(updates);
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(location, "location");
    }
}

