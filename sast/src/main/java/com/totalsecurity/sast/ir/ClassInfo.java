package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

public record ClassInfo(
        TypeKind kind,
        String name,
        List<AnnotationInfo> annotations,
        List<VariableInfo> fields,
        List<MethodInfo> methods,
        SourceLocation location) {
    public ClassInfo {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        annotations = List.copyOf(annotations);
        fields = List.copyOf(fields);
        methods = List.copyOf(methods);
        Objects.requireNonNull(location, "location");
    }
}

