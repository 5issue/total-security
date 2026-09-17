package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record CrossClassInterproceduralResult(
        ProjectClassIndex classIndex,
        Map<ProjectMethodId, SameClassMethodSummary> methodSummaries,
        Map<ProjectMethodId, RuleAwareTaintResult> methodAnalyses,
        List<ProjectCallResolution> callResolutions,
        List<UnsupportedInterproceduralFlow> unsupported,
        List<Finding> findings) {
    public CrossClassInterproceduralResult {
        methodSummaries = Map.copyOf(new LinkedHashMap<>(methodSummaries));
        methodAnalyses = Map.copyOf(new LinkedHashMap<>(methodAnalyses));
        callResolutions = List.copyOf(callResolutions);
        unsupported = List.copyOf(unsupported);
        findings = List.copyOf(findings);
    }
}
