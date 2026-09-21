package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Explicit AUTHN-11 limitation for a persistence occurrence that cannot be source-proven. */
public record UnsupportedAuthn11Flow(String reason, SourceLocation location) {
    public UnsupportedAuthn11Flow {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
