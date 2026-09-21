package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.VariableInfo;
import java.util.Objects;

/** Exact source evidence for one compiler-generated Lombok getter occurrence. */
public record LombokGetterInfo(
        String ownerQualifiedName,
        String qualifiedReturnType,
        String getterName,
        VariableInfo field) {
    public LombokGetterInfo {
        Objects.requireNonNull(ownerQualifiedName, "ownerQualifiedName");
        Objects.requireNonNull(qualifiedReturnType, "qualifiedReturnType");
        Objects.requireNonNull(getterName, "getterName");
        Objects.requireNonNull(field, "field");
    }
}
