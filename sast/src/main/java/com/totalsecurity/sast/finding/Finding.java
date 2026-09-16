package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;

/** Tree-sitter-independent vulnerability evidence model. */
public record Finding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        List<FindingSource> sources,
        FindingSink sink,
        List<FindingFlow> flows,
        String evidence) {
    public Finding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        sources = List.copyOf(sources);
        Objects.requireNonNull(sink, "sink");
        flows = List.copyOf(flows);
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
