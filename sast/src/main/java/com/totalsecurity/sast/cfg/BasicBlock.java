package com.totalsecurity.sast.cfg;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.statement.Statement;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** An immutable CFG block containing statements in their execution order. */
public record BasicBlock(
        int id,
        BasicBlockKind kind,
        String label,
        List<Statement> statements,
        Optional<Statement> controlStatement,
        SourceLocation location) {
    public BasicBlock {
        if (id < 0) {
            throw new IllegalArgumentException("Block id must be non-negative");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(label, "label");
        statements = List.copyOf(statements);
        controlStatement = Objects.requireNonNull(controlStatement, "controlStatement");
        Objects.requireNonNull(location, "location");
    }
}

