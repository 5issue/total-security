package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

public record ClassInfo(
        TypeKind kind,
        String name,
        List<String> extendsTypes,
        List<String> implementsTypes,
        List<AnnotationInfo> annotations,
        List<VariableInfo> fields,
        List<MethodInfo> methods,
        SourceLocation location) {
    public ClassInfo {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        extendsTypes = List.copyOf(extendsTypes);
        implementsTypes = List.copyOf(implementsTypes);
        annotations = List.copyOf(annotations);
        fields = List.copyOf(fields);
        methods = List.copyOf(methods);
        Objects.requireNonNull(location, "location");
    }

    /** Compatibility constructor for callers that do not provide hierarchy metadata. */
    public ClassInfo(
            TypeKind kind,
            String name,
            List<AnnotationInfo> annotations,
            List<VariableInfo> fields,
            List<MethodInfo> methods,
            SourceLocation location) {
        this(kind, name, List.of(), List.of(), annotations, fields, methods, location);
    }
}
