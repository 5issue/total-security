package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.List;
import java.util.Objects;

/** Finding for a source-backed Java native deserialization use without a synthetic argument sink. */
public record DeserializationFinding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        List<FindingSource> sources,
        List<FindingFlow> flows,
        String deserializerType,
        List<DeserializationEvidence> lineage,
        List<SourceLocation> deserializerCreationLocations,
        SourceLocation deserializationLocation,
        String evidence) implements FindingResult {
    public DeserializationFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        sources = List.copyOf(sources);
        if (sources.isEmpty()) {
            throw new IllegalArgumentException("sources must not be empty");
        }
        flows = List.copyOf(flows);
        if (flows.isEmpty()) {
            throw new IllegalArgumentException("flows must not be empty");
        }
        requireText(deserializerType, "deserializerType");
        lineage = List.copyOf(lineage);
        if (lineage.isEmpty()) {
            throw new IllegalArgumentException("lineage must not be empty");
        }
        deserializerCreationLocations = List.copyOf(deserializerCreationLocations);
        if (deserializerCreationLocations.isEmpty()) {
            throw new IllegalArgumentException("deserializerCreationLocations must not be empty");
        }
        Objects.requireNonNull(deserializationLocation, "deserializationLocation");
        if (!primaryLocation.equals(deserializationLocation)) {
            throw new IllegalArgumentException("primaryLocation must identify readObject");
        }
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
