package com.totalsecurity.sast.ir;

import com.totalsecurity.sast.ir.expression.Expression;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record VariableInfo(
        VariableKind kind,
        String name,
        String type,
        List<AnnotationInfo> annotations,
        Optional<Expression> initializer,
        boolean staticMember,
        SourceLocation location) {
    public VariableInfo {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(type, "type");
        annotations = List.copyOf(annotations);
        initializer = Objects.requireNonNull(initializer, "initializer");
        Objects.requireNonNull(location, "location");
    }

    /** Compatibility constructor for variables whose declaration modifiers are not supplied. */
    public VariableInfo(
            VariableKind kind,
            String name,
            String type,
            List<AnnotationInfo> annotations,
            Optional<Expression> initializer,
            SourceLocation location) {
        this(kind, name, type, annotations, initializer, false, location);
    }
}
