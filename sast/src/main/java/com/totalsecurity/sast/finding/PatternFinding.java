package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;

/** Finding evidence for a structural pattern that has no source-to-sink flow. */
public record PatternFinding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        String identifier,
        PatternOccurrenceKind occurrenceKind,
        String literalKind,
        String evidence) implements FindingResult {
    public PatternFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        requireText(identifier, "identifier");
        Objects.requireNonNull(occurrenceKind, "occurrenceKind");
        requireText(literalKind, "literalKind");
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
