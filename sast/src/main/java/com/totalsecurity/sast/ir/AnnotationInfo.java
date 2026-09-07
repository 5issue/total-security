package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

/** Syntactic annotation information without framework-specific semantics. */
public record AnnotationInfo(String name, List<String> arguments, SourceLocation location) {
    public AnnotationInfo {
        Objects.requireNonNull(name, "name");
        arguments = List.copyOf(arguments);
        Objects.requireNonNull(location, "location");
    }
}

