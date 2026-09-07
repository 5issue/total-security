package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

public record ParameterInfo(
        String name, String type, List<AnnotationInfo> annotations, SourceLocation location) {
    public ParameterInfo {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(type, "type");
        annotations = List.copyOf(annotations);
        Objects.requireNonNull(location, "location");
    }
}

