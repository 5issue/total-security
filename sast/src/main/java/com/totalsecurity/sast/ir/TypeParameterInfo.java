package com.totalsecurity.sast.ir;

import java.util.List;
import java.util.Objects;

/** A declared method type parameter and its explicitly written upper bounds. */
public record TypeParameterInfo(
        String name,
        List<String> upperBounds,
        SourceLocation location) {
    public TypeParameterInfo {
        Objects.requireNonNull(name, "name");
        upperBounds = List.copyOf(upperBounds);
        Objects.requireNonNull(location, "location");
    }
}
