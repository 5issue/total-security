package com.totalsecurity.sast.detector.upload;

import com.totalsecurity.sast.finding.FileUploadEvidence;
import com.totalsecurity.sast.taint.TaintSeed;
import java.util.List;
import java.util.Set;

/** Target-control result plus the static origins and constructions that justify it. */
public record FileUploadTargetAssessment(
        FileUploadTargetControl control,
        Set<TaintSeed> origins,
        List<FileUploadEvidence> constructionEvidence) {
    public FileUploadTargetAssessment {
        origins = Set.copyOf(origins);
        constructionEvidence = List.copyOf(constructionEvidence);
    }
}
