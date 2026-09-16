package com.totalsecurity.sast.finding;

import java.util.List;
import java.util.Objects;

public record FindingFlow(FindingSource source, List<FindingFlowStep> steps) {
    public FindingFlow {
        Objects.requireNonNull(source, "source");
        steps = List.copyOf(steps);
        if (steps.isEmpty()) {
            throw new IllegalArgumentException("Finding flow must contain at least one step");
        }
    }
}
