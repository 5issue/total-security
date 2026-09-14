package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record UnsupportedDataFlow(String construct, String reason, SourceLocation location) {
    public UnsupportedDataFlow {
        Objects.requireNonNull(construct, "construct");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(location, "location");
    }
}
