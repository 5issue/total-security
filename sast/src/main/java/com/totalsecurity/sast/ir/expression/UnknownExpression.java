package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** An explicitly unsupported expression; no semantic meaning is inferred. */
public record UnknownExpression(
        String syntaxKind, String source, SourceLocation location) implements Expression {
    public UnknownExpression {
        Objects.requireNonNull(syntaxKind, "syntaxKind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(location, "location");
    }
}

