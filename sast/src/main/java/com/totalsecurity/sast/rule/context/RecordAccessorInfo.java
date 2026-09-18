package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.RecordComponentInfo;
import java.util.Objects;

/** Exact compiler-provided record accessor proven from one unique source declaration. */
public record RecordAccessorInfo(
        String ownerQualifiedName,
        String qualifiedReturnType,
        RecordComponentInfo component) {
    public RecordAccessorInfo {
        if (ownerQualifiedName == null || ownerQualifiedName.isBlank()) {
            throw new IllegalArgumentException("ownerQualifiedName must not be blank");
        }
        if (qualifiedReturnType == null || qualifiedReturnType.isBlank()) {
            throw new IllegalArgumentException("qualifiedReturnType must not be blank");
        }
        Objects.requireNonNull(component, "component");
    }
}
