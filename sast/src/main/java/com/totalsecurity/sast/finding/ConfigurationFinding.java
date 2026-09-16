package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;

/** Finding for an explicit unsafe configuration linked to a concrete component use. */
public record ConfigurationFinding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        String factoryType,
        String parserType,
        List<ConfigurationEvidence> configurations,
        SourceLocation parserCreationLocation,
        SourceLocation parserUseLocation,
        String evidence) implements FindingResult {
    public ConfigurationFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        requireText(factoryType, "factoryType");
        requireText(parserType, "parserType");
        configurations = List.copyOf(configurations);
        if (configurations.isEmpty()) {
            throw new IllegalArgumentException("configurations must not be empty");
        }
        Objects.requireNonNull(parserCreationLocation, "parserCreationLocation");
        Objects.requireNonNull(parserUseLocation, "parserUseLocation");
        if (!primaryLocation.equals(parserUseLocation)) {
            throw new IllegalArgumentException("primaryLocation must identify the parser use");
        }
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
