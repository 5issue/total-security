package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;
import java.util.Optional;

public record BreakStatement(Optional<String> label, SourceLocation location) implements Statement {
    public BreakStatement {
        label = Objects.requireNonNull(label, "label");
        Objects.requireNonNull(location, "location");
    }
}

