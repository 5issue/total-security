package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import java.util.Objects;

public record DoWhileStatement(
        Statement body, Expression condition, SourceLocation location) implements Statement {
    public DoWhileStatement {
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(condition, "condition");
        Objects.requireNonNull(location, "location");
    }
}

