package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Exact HTML context, writer derivation, or output occurrence supporting an XSS finding. */
public record XssEvidence(XssEvidenceKind kind, String detail, SourceLocation location) {
    public XssEvidence {
        Objects.requireNonNull(kind, "kind");
        if (detail == null || detail.isBlank()) {
            throw new IllegalArgumentException("detail must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
