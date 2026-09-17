package com.totalsecurity.sast.detector.redirect;

/** How much externally supplied input controls the beginning of a redirect target. */
public enum RedirectTargetControl {
    CLEAN,
    FULLY_CONTROLLED,
    FIXED_PREFIX,
    UNKNOWN;

    /** May-analysis merge used for alternative reaching definitions. */
    public RedirectTargetControl join(RedirectTargetControl other) {
        if (this == FULLY_CONTROLLED || other == FULLY_CONTROLLED) {
            return FULLY_CONTROLLED;
        }
        if (this == UNKNOWN || other == UNKNOWN) {
            return UNKNOWN;
        }
        if (this == FIXED_PREFIX || other == FIXED_PREFIX) {
            return FIXED_PREFIX;
        }
        return CLEAN;
    }
}
