package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.Objects;
import java.util.Optional;

public record ProjectCallResolution(
        ProjectMethodId caller,
        MethodCallExpression call,
        SameClassCallStatus status,
        Optional<ProjectMethodId> target,
        Optional<UnsupportedInterproceduralFlow> unsupported) {
    public ProjectCallResolution {
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(call, "call");
        Objects.requireNonNull(status, "status");
        target = Objects.requireNonNull(target, "target");
        unsupported = Objects.requireNonNull(unsupported, "unsupported");
        if ((status == SameClassCallStatus.RESOLVED) != target.isPresent()) {
            throw new IllegalArgumentException("Resolved calls require exactly one target");
        }
        if ((status == SameClassCallStatus.UNSUPPORTED) != unsupported.isPresent()) {
            throw new IllegalArgumentException("Unsupported calls require a reason");
        }
    }
}
