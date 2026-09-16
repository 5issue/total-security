package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

public record FindingFlowStep(
        FindingFlowStepKind kind, SourceLocation location, String summary) {
    public FindingFlowStep {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(location, "location");
        if (summary == null || summary.isBlank()) {
            throw new IllegalArgumentException("summary must not be blank");
        }
    }
}
