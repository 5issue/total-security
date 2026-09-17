package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.detector.upload.FileUploadTargetControl;
import com.totalsecurity.sast.ir.SourceLocation;
import com.totalsecurity.sast.rule.sink.SinkCategory;
import java.util.List;
import java.util.Objects;

/** Contextual file-upload finding without fabricating a generic taint sink flow. */
public record FileUploadFinding(
        String ruleId,
        String vulnerabilityType,
        String cwe,
        FindingSeverity severity,
        SourceLocation primaryLocation,
        String multipartType,
        String targetType,
        FileUploadTargetControl targetControl,
        FindingSink sink,
        List<FileUploadEvidence> contextEvidence,
        String evidence) implements FindingResult {
    public FileUploadFinding {
        requireText(ruleId, "ruleId");
        requireText(vulnerabilityType, "vulnerabilityType");
        requireText(cwe, "cwe");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(primaryLocation, "primaryLocation");
        requireText(multipartType, "multipartType");
        requireText(targetType, "targetType");
        if (targetControl != FileUploadTargetControl.ATTACKER_TYPE_CONTROLLED) {
            throw new IllegalArgumentException("Confirmed upload requires attacker type control");
        }
        Objects.requireNonNull(sink, "sink");
        if (sink.category() != SinkCategory.FILE_UPLOAD_TARGET || sink.argumentIndex() != 0) {
            throw new IllegalArgumentException("Upload sink must identify transfer target argument 0");
        }
        contextEvidence = List.copyOf(contextEvidence);
        for (FileUploadEvidenceKind required : FileUploadEvidenceKind.values()) {
            if (contextEvidence.stream().noneMatch(item -> item.kind() == required)) {
                throw new IllegalArgumentException("Missing upload evidence: " + required);
            }
        }
        requireText(evidence, "evidence");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
