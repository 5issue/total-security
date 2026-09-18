package com.totalsecurity.sast.ir;

import java.util.Objects;

/** One source-declared enum constant and whether it has a constant-specific class body. */
public record EnumConstantInfo(
        String name, boolean constantSpecificClassBody, SourceLocation location) {
    public EnumConstantInfo {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
