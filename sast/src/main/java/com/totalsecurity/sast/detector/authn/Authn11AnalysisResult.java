package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import java.util.List;

public record Authn11AnalysisResult(
        List<ChecklistFlowFinding> findings,
        List<UnsupportedAuthn11Flow> unsupported) {
    public Authn11AnalysisResult {
        findings = List.copyOf(findings);
        unsupported = List.copyOf(unsupported);
    }
}
