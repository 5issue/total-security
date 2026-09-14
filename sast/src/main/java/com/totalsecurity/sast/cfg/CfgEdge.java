package com.totalsecurity.sast.cfg;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record CfgEdge(
        BasicBlock source,
        BasicBlock target,
        CfgEdgeType type,
        SourceLocation location) {
    public CfgEdge {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(location, "location");
    }
}

