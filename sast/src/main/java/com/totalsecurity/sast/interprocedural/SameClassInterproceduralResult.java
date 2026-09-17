package com.totalsecurity.sast.interprocedural;

import com.totalsecurity.sast.finding.Finding;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.rule.RuleAwareTaintResult;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record SameClassInterproceduralResult(
        Map<MethodInfo, SameClassMethodSummary> methodSummaries,
        Map<MethodInfo, RuleAwareTaintResult> methodAnalyses,
        List<SameClassCallResolution> callResolutions,
        List<UnsupportedInterproceduralFlow> unsupported,
        List<Finding> findings) {
    public SameClassInterproceduralResult {
        methodSummaries = Map.copyOf(new LinkedHashMap<>(methodSummaries));
        methodAnalyses = Map.copyOf(new LinkedHashMap<>(methodAnalyses));
        callResolutions = List.copyOf(callResolutions);
        unsupported = List.copyOf(unsupported);
        findings = List.copyOf(findings);
    }
}
