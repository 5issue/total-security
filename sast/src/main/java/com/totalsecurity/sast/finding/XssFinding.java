package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;
import java.util.Objects;

/** Flow finding augmented with explicit servlet HTML-context and writer-lineage evidence. */
public record XssFinding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        List<FindingSource> sources,
        FindingSink sink,
        List<FindingFlow> flows,
        String responseType,
        List<XssEvidence> contextEvidence,
        SourceLocation outputLocation,
        String evidence) implements FindingResult {
    public XssFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        sources = List.copyOf(sources);
        if (sources.isEmpty()) {
            throw new IllegalArgumentException("sources must not be empty");
        }
        Objects.requireNonNull(sink, "sink");
        if (sink.category() != SinkCategory.HTTP_RESPONSE_BODY) {
            throw new IllegalArgumentException("XSS sink must be an HTTP response body");
        }
        flows = List.copyOf(flows);
        if (flows.isEmpty()) {
            throw new IllegalArgumentException("flows must not be empty");
        }
        requireText(responseType, "responseType");
        contextEvidence = List.copyOf(contextEvidence);
        if (contextEvidence.stream().noneMatch(item -> item.kind() == XssEvidenceKind.CONTENT_TYPE)
                || contextEvidence.stream()
                        .noneMatch(item -> item.kind() == XssEvidenceKind.WRITER_DERIVATION)) {
            throw new IllegalArgumentException("Confirmed XSS requires HTML and writer evidence");
        }
        Objects.requireNonNull(outputLocation, "outputLocation");
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
