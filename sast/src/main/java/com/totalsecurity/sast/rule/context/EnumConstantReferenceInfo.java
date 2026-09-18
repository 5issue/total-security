package com.totalsecurity.sast.rule.context;

import com.totalsecurity.sast.ir.EnumConstantInfo;
import java.util.Objects;

/** Exact enum constant reference proven from one unique source declaration. */
public record EnumConstantReferenceInfo(
        String ownerQualifiedName, EnumConstantInfo constant) {
    public EnumConstantReferenceInfo {
        if (ownerQualifiedName == null || ownerQualifiedName.isBlank()) {
            throw new IllegalArgumentException("ownerQualifiedName must not be blank");
        }
        Objects.requireNonNull(constant, "constant");
    }
}
