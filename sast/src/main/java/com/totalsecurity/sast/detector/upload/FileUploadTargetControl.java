package com.totalsecurity.sast.detector.upload;

/** Whether the final stored filename extension remains controlled by external input. */
public enum FileUploadTargetControl {
    CLEAN,
    ATTACKER_TYPE_CONTROLLED,
    FIXED_EXTENSION,
    UNKNOWN;

    /** May-analysis merge for alternative reaching definitions. */
    public FileUploadTargetControl join(FileUploadTargetControl other) {
        if (this == ATTACKER_TYPE_CONTROLLED || other == ATTACKER_TYPE_CONTROLLED) {
            return ATTACKER_TYPE_CONTROLLED;
        }
        if (this == UNKNOWN || other == UNKNOWN) {
            return UNKNOWN;
        }
        if (this == FIXED_EXTENSION || other == FIXED_EXTENSION) {
            return FIXED_EXTENSION;
        }
        return CLEAN;
    }
}
