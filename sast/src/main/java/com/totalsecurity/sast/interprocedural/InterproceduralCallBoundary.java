package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;
import java.util.Set;

public record InterproceduralCallBoundary(
        MethodInfo caller,
        MethodInfo callee,
        SourceLocation callLocation,
        Set<Integer> calleeParameterIndexes) {
    public InterproceduralCallBoundary {
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(callee, "callee");
        Objects.requireNonNull(callLocation, "callLocation");
        calleeParameterIndexes = Set.copyOf(calleeParameterIndexes);
    }
}
