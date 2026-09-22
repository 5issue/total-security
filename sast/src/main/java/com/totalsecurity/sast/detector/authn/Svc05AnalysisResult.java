package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.finding.ChecklistFlowFinding;
import java.util.List;

public record Svc05AnalysisResult(
        List<ChecklistFlowFinding> findings,
        List<UnsupportedSvc05Flow> unsupported) {
    public Svc05AnalysisResult {
        findings = List.copyOf(findings);
        unsupported = List.copyOf(unsupported);
    }
}
