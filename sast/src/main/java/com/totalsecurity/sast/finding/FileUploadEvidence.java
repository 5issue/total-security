package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** One exact source, construction, or transfer occurrence in a supported upload flow. */
public record FileUploadEvidence(
        FileUploadEvidenceKind kind, String detail, SourceLocation location) {
    public FileUploadEvidence {
        Objects.requireNonNull(kind, "kind");
        if (detail == null || detail.isBlank()) {
            throw new IllegalArgumentException("detail must not be blank");
        }
        Objects.requireNonNull(location, "location");
    }
}
