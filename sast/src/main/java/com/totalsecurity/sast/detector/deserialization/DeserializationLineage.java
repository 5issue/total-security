package com.totalsecurity.sast.detector.deserialization;

import com.totalsecurity.sast.finding.DeserializationEvidence;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.ir.expression.Expression;
import com.totalsecurity.sast.taint.TaintValue;
import java.util.List;
import java.util.Objects;

/** One supported input path into an exact ObjectInputStream construction. */
public record DeserializationLineage(
        TaintValue inputTaint,
        Expression taintEndpoint,
        List<DeserializationEvidence> evidence,
        SourceLocation objectInputStreamCreationLocation) {
    public DeserializationLineage {
        Objects.requireNonNull(inputTaint, "inputTaint");
        Objects.requireNonNull(taintEndpoint, "taintEndpoint");
        evidence = List.copyOf(evidence);
        if (evidence.isEmpty()) {
            throw new IllegalArgumentException("evidence must not be empty");
        }
        Objects.requireNonNull(objectInputStreamCreationLocation, "objectInputStreamCreationLocation");
    }
}
