package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;

public record BlockStatement(List<Statement> statements, SourceLocation location) implements Statement {
    public BlockStatement {
        statements = List.copyOf(statements);
        Objects.requireNonNull(location, "location");
    }
}

