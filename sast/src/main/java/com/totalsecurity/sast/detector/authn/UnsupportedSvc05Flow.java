package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Explicit SVC-05 limitation for a broker payload occurrence that cannot be source-proven. */
public record UnsupportedSvc05Flow(String reason, SourceLocation location) {
    public UnsupportedSvc05Flow {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
