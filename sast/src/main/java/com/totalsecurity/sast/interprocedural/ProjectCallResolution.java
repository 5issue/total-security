package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.expression.MethodCallExpression;
import java.util.Objects;
import java.util.Optional;

public record ProjectCallResolution(
        ProjectMethodId caller,
        MethodCallExpression call,
        SameClassCallStatus status,
        Optional<ProjectMethodId> target,
        Optional<UnsupportedInterproceduralFlow> unsupported,
        Optional<InterfaceDispatchInfo> interfaceDispatch) {
    public ProjectCallResolution {
        Objects.requireNonNull(caller, "caller");
        Objects.requireNonNull(call, "call");
        Objects.requireNonNull(status, "status");
        target = Objects.requireNonNull(target, "target");
        unsupported = Objects.requireNonNull(unsupported, "unsupported");
        interfaceDispatch = Objects.requireNonNull(interfaceDispatch, "interfaceDispatch");
        if ((status == SameClassCallStatus.RESOLVED) != target.isPresent()) {
            throw new IllegalArgumentException("Resolved calls require exactly one target");
        }
        if ((status == SameClassCallStatus.UNSUPPORTED) != unsupported.isPresent()) {
            throw new IllegalArgumentException("Unsupported calls require a reason");
        }
        if (status == SameClassCallStatus.MODELED
                && (target.isPresent() || unsupported.isPresent())) {
            throw new IllegalArgumentException("Modeled calls have no method target or unsupported reason");
        }
        if (interfaceDispatch.isPresent() && status != SameClassCallStatus.RESOLVED) {
            throw new IllegalArgumentException("Interface dispatch metadata requires a resolved call");
        }
        if (interfaceDispatch.isPresent()
                && !interfaceDispatch.orElseThrow().resolvedImplementation()
                        .equals(target.orElseThrow().ownerQualifiedName())) {
            throw new IllegalArgumentException("Interface dispatch implementation must match target owner");
        }
    }

    public ProjectCallResolution(
            ProjectMethodId caller,
            MethodCallExpression call,
            SameClassCallStatus status,
            Optional<ProjectMethodId> target,
            Optional<UnsupportedInterproceduralFlow> unsupported) {
        this(caller, call, status, target, unsupported, Optional.empty());
    }
}
