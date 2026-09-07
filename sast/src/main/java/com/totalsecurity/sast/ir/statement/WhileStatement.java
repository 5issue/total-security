package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record WhileStatement(
        Expression condition, Statement body, SourceLocation location) implements Statement {
    public WhileStatement {
        Objects.requireNonNull(condition, "condition");
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(location, "location");
    }
}

