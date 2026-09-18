package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

/** One source-declared record component, independent of Tree-sitter nodes. */
public record RecordComponentInfo(
        String name,
        String declaredType,
        List<AnnotationInfo> annotations,
        SourceLocation location) {
    public RecordComponentInfo {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        if (declaredType == null || declaredType.isBlank()) {
            throw new IllegalArgumentException("declaredType must not be blank");
        }
        annotations = List.copyOf(annotations);
        Objects.requireNonNull(location, "location");
    }
}
