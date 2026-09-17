package com.totalsecurity.sast.detector.xss;

/** Proven state of one directly tracked servlet response's content type. */
public enum HttpResponseContentType {
    HTML,
    NON_HTML,
    UNKNOWN,
    UNSET;

    public HttpResponseContentType join(HttpResponseContentType other) {
        return this == other ? this : UNKNOWN;
    }
}
