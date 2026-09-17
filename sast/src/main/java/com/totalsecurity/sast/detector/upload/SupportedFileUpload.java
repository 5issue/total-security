package com.totalsecurity.sast.detector.upload;

import com.totalsecurity.sast.finding.FileUploadEvidence;
import com.totalsecurity.sast.rule.sink.SinkMatch;
import com.totalsecurity.sast.rule.source.ParameterSourceMatch;
import java.util.List;
import java.util.Objects;

/** One exact external MultipartFile transfer and its destination control assessment. */
public record SupportedFileUpload(
        SinkMatch sink,
        ParameterSourceMatch multipartSource,
        String targetType,
        FileUploadTargetAssessment target,
        List<FileUploadEvidence> evidence) {
    public SupportedFileUpload {
        Objects.requireNonNull(sink, "sink");
        Objects.requireNonNull(multipartSource, "multipartSource");
        Objects.requireNonNull(targetType, "targetType");
        Objects.requireNonNull(target, "target");
        evidence = List.copyOf(evidence);
    }
}
