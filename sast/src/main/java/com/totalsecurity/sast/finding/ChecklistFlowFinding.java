package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Source-proven policy finding whose checklist does not provide a CWE mapping. */
public record ChecklistFlowFinding(
        String ruleId,
        String checklistId,
        String vulnerabilityType,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        List<FindingSource> sources,
        FindingSink sink,
        List<FindingFlow> flows,
        String evidence) implements FindingResult {
    public ChecklistFlowFinding {
        requireText(ruleId, "ruleId");
        requireText(checklistId, "checklistId");
        requireText(vulnerabilityType, "vulnerabilityType");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        sources = List.copyOf(sources);
        if (sources.isEmpty()) {
            throw new IllegalArgumentException("sources must not be empty");
        }
        Objects.requireNonNull(sink, "sink");
        flows = List.copyOf(flows);
        if (flows.isEmpty()) {
            throw new IllegalArgumentException("flows must not be empty");
        }
        requireText(evidence, "evidence");
    }

    @Override
    public String cwe() {
        return "";
    }

    @Override
    public Optional<String> cweReference() {
        return Optional.empty();
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
