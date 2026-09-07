package com.totalsecurity.sast.ir.expression;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record VariableReference(String name, SourceLocation location) implements Expression {
    public VariableReference {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(location, "location");
    }
}

