package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.ir.MethodInfo;
import java.util.Objects;
import java.util.stream.Collectors;

/** Owner-qualified method identity used by the project-local call graph. */
public record ProjectMethodId(String ownerQualifiedName, MethodInfo method) {
    public ProjectMethodId {
        if (ownerQualifiedName == null || ownerQualifiedName.isBlank()) {
            throw new IllegalArgumentException("ownerQualifiedName must not be blank");
        }
        Objects.requireNonNull(method, "method");
    }

    public String displayName() {
        return ownerQualifiedName + "#" + method.name() + "(" + method.parameters().stream()
                .map(parameter -> parameter.type())
                .collect(Collectors.joining(",")) + ")";
    }

    public String boundaryName() {
        return ownerQualifiedName + "#" + method.name();
    }
}
