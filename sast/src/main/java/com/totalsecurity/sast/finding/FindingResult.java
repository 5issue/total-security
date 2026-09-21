package com.totalsecurity.sast.finding;

import com.totalsecurity.sast.ir.SourceLocation;
import java.util.Optional;

/** Common metadata exposed by flow, configuration, pattern, and contextual findings. */
public interface FindingResult {
    String ruleId();

    String vulnerabilityType();

    String cwe();

    /** Optional CWE metadata for rules whose source specification provides no CWE mapping. */
    default Optional<String> cweReference() {
        return Optional.of(cwe());
    }

    FindingSeverity severity();

    SourceLocation primaryLocation();

    String evidence();
}
