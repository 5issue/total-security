package com.totalsecurity.sast.detector.xss;

/** Context-specific safety of a String written into an HTML response body. */
public enum HtmlOutputSafety {
    CLEAN,
    HTML_ESCAPED,
    UNKNOWN,
    RAW_TAINTED;

    public HtmlOutputSafety join(HtmlOutputSafety other) {
        if (this == RAW_TAINTED || other == RAW_TAINTED) {
            return RAW_TAINTED;
        }
        if (this == UNKNOWN || other == UNKNOWN) {
            return UNKNOWN;
        }
        if (this == HTML_ESCAPED || other == HTML_ESCAPED) {
            return HTML_ESCAPED;
        }
        return CLEAN;
    }
}
