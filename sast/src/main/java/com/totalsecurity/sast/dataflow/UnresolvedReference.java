package com.totalsecurity.sast.dataflow;

import com.totalsecurity.sast.ir.expression.VariableReference;
import java.util.Objects;

public record UnresolvedReference(VariableReference reference, String reason) {
    public UnresolvedReference {
        Objects.requireNonNull(reference, "reference");
        Objects.requireNonNull(reason, "reason");
    }
}
