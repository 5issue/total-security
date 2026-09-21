package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

public record ClassInfo(
        TypeKind kind,
        String name,
        List<String> enclosingTypeNames,
        boolean abstractType,
        List<String> extendsTypes,
        List<String> implementsTypes,
        List<AnnotationInfo> annotations,
        List<VariableInfo> fields,
        List<MethodInfo> methods,
        List<RecordComponentInfo> recordComponents,
        List<EnumConstantInfo> enumConstants,
        SourceLocation location) {
    public ClassInfo {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
        enclosingTypeNames = List.copyOf(enclosingTypeNames);
        if (enclosingTypeNames.stream().anyMatch(value -> value == null || value.isBlank())) {
            throw new IllegalArgumentException("enclosingTypeNames must not contain blanks");
        }
        extendsTypes = List.copyOf(extendsTypes);
        implementsTypes = List.copyOf(implementsTypes);
        annotations = List.copyOf(annotations);
        fields = List.copyOf(fields);
        methods = List.copyOf(methods);
        recordComponents = List.copyOf(recordComponents);
        enumConstants = List.copyOf(enumConstants);
        Objects.requireNonNull(location, "location");
    }

    /** Source-level type name, retaining the enclosing member-type path with dots. */
    public String sourceName() {
        return enclosingTypeNames.isEmpty()
                ? name
                : String.join(".", enclosingTypeNames) + "." + name;
    }

    /** Compatibility constructor for top-level types with record/enum-specific metadata. */
    public ClassInfo(
            TypeKind kind,
            String name,
            boolean abstractType,
            List<String> extendsTypes,
            List<String> implementsTypes,
            List<AnnotationInfo> annotations,
            List<VariableInfo> fields,
            List<MethodInfo> methods,
            List<RecordComponentInfo> recordComponents,
            List<EnumConstantInfo> enumConstants,
            SourceLocation location) {
        this(kind, name, List.of(), abstractType, extendsTypes, implementsTypes, annotations,
                fields, methods, recordComponents, enumConstants, location);
    }

    /** Compatibility constructor for types without record/enum-specific metadata. */
    public ClassInfo(
            TypeKind kind,
            String name,
            boolean abstractType,
            List<String> extendsTypes,
            List<String> implementsTypes,
            List<AnnotationInfo> annotations,
            List<VariableInfo> fields,
            List<MethodInfo> methods,
            SourceLocation location) {
        this(kind, name, List.of(), abstractType, extendsTypes, implementsTypes, annotations, fields, methods,
                List.of(), List.of(), location);
    }

    /** Compatibility constructor for non-abstract types without record/enum metadata. */
    public ClassInfo(
            TypeKind kind,
            String name,
            List<String> extendsTypes,
            List<String> implementsTypes,
            List<AnnotationInfo> annotations,
            List<VariableInfo> fields,
            List<MethodInfo> methods,
            SourceLocation location) {
        this(kind, name, List.of(), false, extendsTypes, implementsTypes, annotations, fields, methods,
                List.of(), List.of(), location);
    }

    /** Compatibility constructor for callers that do not provide hierarchy metadata. */
    public ClassInfo(
            TypeKind kind,
            String name,
            List<AnnotationInfo> annotations,
            List<VariableInfo> fields,
            List<MethodInfo> methods,
            SourceLocation location) {
        this(kind, name, List.of(), false, List.of(), List.of(), annotations, fields, methods,
                List.of(), List.of(), location);
    }
}
