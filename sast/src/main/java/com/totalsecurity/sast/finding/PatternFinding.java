package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Objects;
import java.util.Optional;

/** Finding evidence for a structural pattern that has no source-to-sink flow. */
public record PatternFinding(
        String ruleId,
        String vulnerabilityType,
        Optional<String> cweReference,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        String identifier,
        PatternOccurrenceKind occurrenceKind,
        String literalKind,
        String evidence) implements FindingResult {
    public PatternFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        cweReference = Objects.requireNonNull(cweReference, "cweReference");
        cweReference.ifPresent(value -> requireText(value, "cweReference value"));
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        requireText(identifier, "identifier");
        Objects.requireNonNull(occurrenceKind, "occurrenceKind");
        requireText(literalKind, "literalKind");
        requireText(evidence, "evidence");
    }

    /** Compatibility constructor for existing CWE-bearing pattern findings. */
    public PatternFinding(
            String ruleId,
            String vulnerabilityType,
            String cwe,
            FindingSeverity severity,
            SourceLocation primaryLocation,
            String identifier,
            PatternOccurrenceKind occurrenceKind,
            String literalKind,
            String evidence) {
        this(
                ruleId,
                vulnerabilityType,
                Optional.of(requireTextValue(cwe, "cwe")),
                severity,
                primaryLocation,
                identifier,
                occurrenceKind,
                literalKind,
                evidence);
    }

    @Override
    public String cwe() {
        return cweReference.orElse("");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    private static String requireTextValue(String value, String name) {
        requireText(value, name);
        return value;
    }
}
