package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** A method-local variable identity established from a concrete lexical declaration. */
public record VariableSymbol(
        int id,
        String name,
        VariableSymbolKind kind,
        String declaredType,
        SourceLocation declarationLocation) {
    public VariableSymbol {
        if (id < 0) {
            throw new IllegalArgumentException("Symbol id must be non-negative");
        }
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(declaredType, "declaredType");
        Objects.requireNonNull(declarationLocation, "declarationLocation");
    }
}
