package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** An unsupported statement retained without inferring control-flow behavior. */
public record UnknownStatement(
        String syntaxKind, String source, SourceLocation location) implements Statement {
    public UnknownStatement {
        Objects.requireNonNull(syntaxKind, "syntaxKind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(location, "location");
    }
}

