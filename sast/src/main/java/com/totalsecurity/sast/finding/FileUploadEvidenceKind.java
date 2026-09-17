package com.totalsecurity.sast.finding;

public enum FileUploadEvidenceKind {
    MULTIPART_SOURCE,
    FILENAME_SOURCE,
    TARGET_CONSTRUCTION,
    TRANSFER
}
