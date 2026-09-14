package com.totalsecurity.sast.cfg;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record UnsupportedControlFlow(
        String construct, String reason, SourceLocation location) {
    public UnsupportedControlFlow {
        Objects.requireNonNull(construct, "construct");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(location, "location");
    }
}

