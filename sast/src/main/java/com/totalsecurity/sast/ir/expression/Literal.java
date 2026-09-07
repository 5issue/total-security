package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Literal source spelling and its grammar kind. */
public record Literal(String kind, String source, SourceLocation location) implements Expression {
    public Literal {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(location, "location");
    }
}

