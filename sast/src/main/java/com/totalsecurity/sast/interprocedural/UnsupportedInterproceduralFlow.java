package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record UnsupportedInterproceduralFlow(
        UnsupportedInterproceduralReason reason, String detail, SourceLocation location) {
    public UnsupportedInterproceduralFlow {
        Objects.requireNonNull(reason, "reason");
        if (detail == null || detail.isBlank()) {
            throw new IllegalArgumentException("detail must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
