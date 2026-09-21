package com.totalsecurity.sast.ir.statement;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;
import java.util.Optional;

/** An unsupported statement retained without inferring control-flow behavior. */
public record UnknownStatement(
        String syntaxKind,
        String source,
        SourceLocation location,
        Optional<TryStatementInfo> tryStatement) implements Statement {
    public UnknownStatement {
        Objects.requireNonNull(syntaxKind, "syntaxKind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(location, "location");
        tryStatement = Objects.requireNonNull(tryStatement, "tryStatement");
    }

    public UnknownStatement(String syntaxKind, String source, SourceLocation location) {
        this(syntaxKind, source, location, Optional.empty());
    }
}
