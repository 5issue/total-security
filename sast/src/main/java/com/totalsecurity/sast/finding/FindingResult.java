package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;

/** Common metadata exposed by flow and pattern findings. */
public interface FindingResult {
    String ruleId();

    String vulnerabilityType();

    String cwe();

    FindingSeverity severity();

    SourceLocation primaryLocation();

    String evidence();
}
