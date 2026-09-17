package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.MethodInfo;
import java.util.List;

public record SameClassMethodSummary(
        MethodInfo method,
        MethodReturnDependency returnDependency,
        List<InterproceduralSinkDependency> sinkDependencies,
        List<UnsupportedInterproceduralFlow> unsupported) {
    public SameClassMethodSummary {
        sinkDependencies = List.copyOf(sinkDependencies);
        unsupported = List.copyOf(unsupported);
    }
}
