package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record FindingSource(
        String sourceRuleId,
        String seedId,
        FindingSourceKind kind,
        SourceLocation location,
        String summary,
        String evidence) {
    public FindingSource {
        requireText(sourceRuleId, "sourceRuleId");
        requireText(seedId, "seedId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(location, "location");
        requireText(summary, "summary");
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
