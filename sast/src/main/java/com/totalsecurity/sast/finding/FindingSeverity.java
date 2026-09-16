package com.totalsecurity.sast.finding;

/** Detector metadata severity; this is not a computed CVSS score. */
public enum FindingSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
